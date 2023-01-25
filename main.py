#!/usr/bin/env python3

# https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/
# pip install pillow
# https://pillow.readthedocs.io/en/stable/reference
# https://pypi.org/project/ImageHash/
# pip install thefuzz[speedup]
# https://github.com/seatgeek/thefuzz
# https://github.com/AUTOMATIC1111/stable-diffusion-webui-tokenizer

import argparse
from pathlib import Path
#from typing import Iterable
from glob import glob
from PIL import Image, UnidentifiedImageError
import sqlite3
from sqlite3 import Error
import json
import sys, os
import logging
import hashlib
import time
import re
from thefuzz import fuzz, process
#from pprint import PrettyPrinter
#import imagehash
from enum import Enum

DEFAULT_DB_FILE = str(Path.home()) + "/ai_meta.db"
DEFAULT_LOG_FILE = str(Path.home()) + "/ai_meta.log"
DEFAULT_LOGLEVEL_FILE = "INFO"
DEFAULT_LOGLEVEL_CL = "ERROR"

class Mode(Enum):
    UPDATEDB = 1
    MATCHDB = 2

log = logging
args = None
conn = None
mode = Mode.MATCHDB



# parse and return command line arguments
def args_init():
    parser = argparse.ArgumentParser(description='AIMetaDB - A Invoke-AI PNG file metadata processor')
    parser.add_argument('infile', type=Path, nargs='+',
                        help='One or more file names, directories, or glob patterns')
    parser.add_argument('--mode', type=str, default='UPDATEDB',
                        choices=['UPDATEDB', 'MATCHDB'],
                        help='Processing mode [updatedb: add file meta to db, matchdb: match file meta with db')
    parser.add_argument('--similarity_min', type=int, default=0,
                        help='Filter matchdb mode results based on similarity >= X [default: 0]')
    parser.add_argument('--recursive', action='store_true',
                        help='Process directories and ** glob patterns recursively')
    parser.add_argument('--dbfile', type=str, default=DEFAULT_DB_FILE,
                        help='DB file location [default: %s]' % DEFAULT_DB_FILE)
    parser.add_argument('--logfile', type=str, default=DEFAULT_LOG_FILE,
                        help='Log file location [default: %s]' % DEFAULT_LOG_FILE)
    parser.add_argument('--loglevel_file', type=str, default=DEFAULT_LOGLEVEL_FILE,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level for log file [default: %s]' % DEFAULT_LOGLEVEL_FILE)
    parser.add_argument('--loglevel_cl', type=str, default=DEFAULT_LOGLEVEL_CL,
                        choices=['NONE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level for command line output [default: %s], NONE for quiet mode (results only)' % DEFAULT_LOGLEVEL_CL)
    global args, mode
    args = parser.parse_args()
    mode = Mode[args.mode]


# initialize logger
def log_init(logfile_path, level_file, level_cl):
    # TODO logger args and default file
    # https://docs.python.org/3/howto/logging.html
    logging.basicConfig(filename=logfile_path, #, encoding='utf-8',
                        format='%(asctime)s | %(levelname)s | %(message)s',
                        level=logging.getLevelName(level_file))
    global log
    log = logging.getLogger("app")
    if (level_cl != 'NONE'):
        # output logger info to stderr, any other output to stdout
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.getLevelName(level_cl))
        ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')) #| %(name)s
        log.addHandler(ch)


# create a database connection to a SQLite database
def db_connect(db_file):
    global conn
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row  # we want dict results (vs plain lists)
        log.info("db version: %s" % sqlite3.version)
    except Error as e:
        log.error("unable to create db connection, exiting: %s" % e)
        sys.exit(1)
    # init db (if new)
    #finally:
    #    if db_conn:
    #        db_conn.close()


# initialize db if non-existing
def db_init(dbfile):
    log.info("opening db connection to: %s" % dbfile)
    db_connect(dbfile)
    sql_create_meta_table = """CREATE TABLE IF NOT EXISTS meta (
                                id integer PRIMARY KEY,
                                image_hash text NOT NULL UNIQUE,
                                file_name text,
                                app_id text,
                                app_version text,
                                model_weights text,
                                model_hash text,
                                type text,
                                prompt text,
                                steps integer,
                                cfg_scale float,
                                sampler text,
                                height integer,
                                width integer,
                                seed integer,
                                png_info text,
                                created_at date DEFAULT(DATETIME('now'))
                            ); """

    # keep large details in separate table only to be loaded if necessary
    #sql_create_meta_json_table = """CREATE TABLE IF NOT EXISTS blobs (
    #                                id integer PRIMAY KEY,
    #                                meta_id integer,
    #                                json blob,
    #                                png_info blob,
    #                                FOREIGN KEY(meta_id) REFERENCES meta(id)
    #                            );"""
    try:
        cur = conn.cursor()
        #cur.execute(f"PRAGMA foreign_keys = ON;")
        log.debug("ensuring db table [meta] exists.")
        cur.execute(sql_create_meta_table);
        #log.info("ensuring db table exists: json")
        #cur.execute(sql_create_meta_json_table);
    except Error as e:
        log.error("unable to initialize db, exiting:\n%s" % e)
        sys.exit(1)


def init():
    args_init()
    log_init(args.logfile, args.loglevel_file, args.loglevel_cl)
    db_init(args.dbfile)


def file_hash(path):
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(65536) # arbitrary number to reduce RAM usage
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def get_meta_db_values(path, png, image_hash):
    file_name = os.path.basename(path)
    meta_dict = png.info
    sd_meta = json.loads(meta_dict['sd-metadata'])
    # sd-metadata is a json-string, not a dict, so let's convert it to one
    meta_dict['sd-metadata'] = sd_meta
    meta_json = json.dumps(meta_dict)
    return {"file_name": file_name,
            "app_id": sd_meta['app_id'],
            "app_version": sd_meta['app_version'],
            "model_weights": sd_meta['model_weights'],
            "model_hash": sd_meta['model_hash'],
            "type": sd_meta['image']['type'],
            "prompt": sd_meta['image']['prompt'][0]['prompt'],
            "steps": sd_meta['image']['steps'],
            "cfg_scale": sd_meta['image']['cfg_scale'],
            "sampler": sd_meta['image']['sampler'],
            "height": sd_meta['image']['height'],
            "width": sd_meta['image']['width'],
            "seed": sd_meta['image']['seed'],
            "png_info": meta_json,
            "image_hash": image_hash}


def db_get_meta_file_name_by_hash(image_hash):
    sql_select = """SELECT file_name FROM meta WHERE image_hash = :image_hash;"""
    cur = conn.cursor()
    cur.execute(sql_select, {"image_hash": image_hash})
    return cur.fetchone() is not None


def db_insert_meta(path, png, image_hash):
    log.debug("inserting meta in db for [image_hash: %s, path: \"%s\"" % (image_hash, path_str))
    sql_insert_meta = """INSERT INTO meta (file_name, app_id, app_version,
                                           model_weights, model_hash, type, prompt,
                                           steps, cfg_scale, sampler,
                                           height, width, seed, png_info,
                                           image_hash)
                         VALUES (:file_name, :app_id, :app_version,
                                 :model_weights, :model_hash, :type, :prompt,
                                 :steps, :cfg_scale, :sampler,
                                 :height, :width, :seed, :png_info,
                                 :image_hash);"""
    try:
        cur = conn.cursor()
        meta_values = get_meta_db_values(path, png, image_hash);
        log.debug("db INSERT into meta: %s" % str(meta_values))
        cur.execute(sql_insert_meta, meta_values)
        conn.commit()
    except KeyError as e:
        log.warning("skipping corrupted or non-invoke-ai [file_path: %s]" % path)
    except sqlite3.IntegrityError:
        res = cur.execute("SELECT file_name FROM meta WHERE image_hash = ?", (image_hash,))
        # todo: compare file names
        val = res.fetchone()
        if (val[0] == file_name):
            log.info("skipping existing entry: [hash_hase: %s, file_name_old: \"%s\", file_name_new: \"%s\"]" % (image_hash, val[0], file_name))
        else:
            log.info("skipping existing entry: [hash_hase: %s, file_name: \"%s\"]" % (image_hash, file_name))
        log.debug("failed to insert duplicate png into db, existing record: %s" % str(val))
        conn.rollback()
    except Error as e:
        log.error("failed to insert new meta into db, transaction rollback:\n" % e)
        conn.rollback()


def db_update_meta(path, png, image_hash):
    log.debug("updating meta in db for [image_hash: %s, path: \"%s\"" % (image_hash, str(path)))
    sql_update_meta = """UPDATE meta
                         SET file_name = :file_name, app_id = :app_id, app_version = :app_version,
                             model_weights = :model_weights, model_hash = :model_hash, type = :type, prompt = :prompt,
                             steps = :steps, cfg_scale = :cfg_scale, sampler = :sampler,
                             height = :height, width = :width, seed = :seed, png_info = :png_info
                         WHERE image_hash = :image_hash;"""
    try:
        cur = conn.cursor()
        meta_values = get_meta_db_values(path, png, image_hash);
        log.debug("db UPDATE into meta: %s" % str(meta_values))
        cur.execute(sql_update_meta, meta_values)
        conn.commit()
    except KeyError as e:
        log.warning("skipping corrupted or non-invoke-ai [file_path: %s]" % path)
    except Error as e:
        log.error("failed to update existing meta in db, transaction rollback:\n" % e)
        conn.rollback()


def db_update_or_create_meta(path, png, image_hash):
    file_name_org = db_get_meta_file_name_by_hash(image_hash)
    if (file_name_org == None):
        db_insert_meta(path, png, image_hash)
    else:
        if (file_name_org != os.path.basename(path)):
            log.debug("updating meta, file_name will change from [\"%s\"] to [\"%s\"]" % (file_name_org, os.path.basename(path)))
        db_update_meta(path, png, image_hash)


def get_output_meta(dict):
    # escape double-quotes " in prompt (promt will be within " on output)
    prompt_esc = re.sub(r'(["\\])', r'\\\1', dict['prompt']).strip()
    return (dict['steps'], dict['cfg_scale'], dict['sampler'], dict['height'], dict['width'], dict['seed'],
            dict['model_hash'], dict['model_weights'], dict['type'], dict['image_hash'], dict['file_name'],
            dict['app_id'], dict['app_version'], prompt_esc)


def db_match(path, png, image_hash):
    meta = get_meta_db_values(path, png, image_hash)
    res = []
    sql_select = """SELECT prompt, image_hash, file_name FROM meta;"""
    cur = conn.cursor()
    cur.execute(sql_select)
    result_set = cur.fetchall()
    log.debug("meta for file [\"%s\"]:\n%s" % (path, meta))
    # TODO allow file output (nice to have, redirect possible)
    print("file |  | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | \"%s\"" %
          get_output_meta(meta))
    for row in result_set:
        similarity = fuzz.token_set_ratio(row['prompt'], meta['prompt'])
        if (similarity > args.similarity_min):
            print("db | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | \"%s\"" %
                  ((similarity,) + get_output_meta(meta)))
    cur.close()


def process_file(file_path):
    try:
        png = Image.open(str(file_path))
        png.load() # needed to get for .png EXIF data
    except UnidentifiedImageError:
        log.warning("Not a valid image file, skipping: %s" % file_path)
        return
    image_hash = file_hash(file_path)
    if (mode == Mode.UPDATEDB):
        db_update_or_create_meta(file_path, png, image_hash)
    else:  # Mode.MATCHDB
        db_match(file_path, png, image_hash)


def process_paths():
    start_time_proc = time.time()
    log.info("starting [mode=%s] ..." % args.mode)
    for f in args.infile:
        start_time_path_arg = time.time()
        log.debug("processing [file_arg: \"%s\"] ..." % f)
        # single file or glob expansion
        file_paths = [f] if f.exists() else [Path(p) for p in glob(str(f.expanduser()), recursive=args.recursive)]
        for file_path in file_paths:
            start_time_file = time.time()
            log.info("processing [file: \"%s\"] ..." % file_path)
            process_file(file_path)
            log.debug("finished processing file [exec_time: %ssec, file_path: \"%s\"]" %
                      (round(time.time() - start_time_file, 3), file_path))
        log.debug("finished processing file_arg [exec_time: %ssec, file_arg: \"%s\"]" %
                  (round(time.time() - start_time_path_arg, 3), f))
    log.info("finished [mode=%s, exec_time: %ssec]!" %
             (mode.name, round(time.time() - start_time_proc, 3)))


if __name__ == '__main__':
    init()
    start_time = time.time()
    process_paths()
