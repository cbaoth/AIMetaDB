#!/usr/bin/env python3

# https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/
# pip install --user pillow
# https://pillow.readthedocs.io/en/stable/reference
# https://pypi.org/project/ImageHash/


import argparse
from pathlib import Path
#from typing import Iterable
from glob import glob
from PIL import Image
import sqlite3
from sqlite3 import Error
import json
import sys, os
import logging
import hashlib
import time
#from pprint import PrettyPrinter
#import imagehash

DEFAULT_DB_FILE_NAME = "ai_meta.db"

log = logging
conn = None

# initialize logger
def log_init():
    # TODO logger args and default file
    # https://docs.python.org/3/howto/logging.html
    logging.basicConfig(filename='ai_meta.log', encoding='utf-8',
                        format='%(asctime)s | %(levelname)s | %(message)s',
                        level=logging.DEBUG)
    global log
    log = logging.getLogger("app")
    ch = logging.StreamHandler()
    #ch.setLevel(logging.DEBUG)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')) #| %(name)s
    log.addHandler(ch)


# create a database connection to a SQLite database
def db_connect(db_file):
    global conn
    try:
        conn = sqlite3.connect(db_file)
        log.info("db version: %s" % sqlite3.version)
    except Error as e:
        log.error("unable to create db connection, exiting: %s" % e)
        sys.exit(1)
    # init db (if new)
    #finally:
    #    if db_conn:
    #        db_conn.close()


# initialize db if non-existing
def db_init():
    db_connect(DEFAULT_DB_FILE_NAME)
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

    #sql_create_meta_json_table = """CREATE TABLE IF NOT EXISTS json (
    #                                id integer PRIMAY KEY,
    #                                meta_id integer,
    #                                json blob,
    #                                FOREIGN KEY(meta_id) REFERENCES meta(id)
    #                            );"""
    try:
        cur = conn.cursor()
        cur.execute(f"PRAGMA foreign_keys = ON;")
        log.info("ensuring db table exists: meta")
        cur.execute(sql_create_meta_table);
        #log.info("ensuring db table exists: json")
        #cur.execute(sql_create_meta_json_table);
    except Error as e:
        log.error("unable to initialize db, exiting:\n%s" % e)
        sys.exit(1)


def init():
    log_init()
    db_init()


def args_parse():
        # Instantiate the parser
    parser = argparse.ArgumentParser(description='Invoke-AI PNG file metadata processor')

    # Required positional argument
    parser.add_argument('infile', nargs='+',
                        help='One or more file names or directories')
    # Optional positional argument
    #parser.add_argument('file', type=int, nargs='?',
    #                    help='An optional integer positional argument')
    # Optional argument
    #parser.add_argument('--opt_arg', type=int,
    #                    help='An optional integer argument')
    # Switch
    #parser.add_argument('--switch', action='store_true',
    #                    help='A boolean switch')
    #def expandpath(path_pattern) -> Iterable[Path]:
    #    p = Path(path_pattern).expanduser()
    #    parts = p.parts[p.is_absolute():]
    #    return Path(p.root).glob(str(Path(*parts)))
    return parser.parse_args()


# https://stackoverflow.com/a/49692185
# def png_hash(png):
#     img = png.resize((10, 10), Image.LANCZOS)
#     img = img.convert("L")
#     pixels = list(img.getdata())
#     avg = sum(pixels)/len(pixels)
#     bits = "".join(['1' if (px >= avg) else '0' for px in pixels])
#     return str(hex(int(bits, 2)))[2:][::-1].upper()


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


def get_meta_db_values(path, png):
    file_name = os.path.basename(path)
    meta_dict = png.info
    sd_meta = json.loads(meta_dict['sd-metadata'])
    # sd-metadata is a json-string, not a dict, so let's convert it to one
    meta_dict['sd-metadata'] = sd_meta
    meta_json = json.dumps(meta_dict)
    image_hash = file_hash(path)
    return {"image_hash": image_hash,
            "file_name": file_name,
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
            "png_info": meta_json}


def db_insert_png(path, png):
    j = json.dumps(png.info, indent = 4)
    log.debug("inserting file metadata into db: %s" % path_str)
    sql_insert_meta = """INSERT INTO meta (image_hash, file_name, app_id, app_version,
                                           model_weights, model_hash, type, prompt,
                                           steps, cfg_scale, sampler,
                                           height, width, seed, png_info)
                         VALUES (:image_hash, :file_name, :app_id, :app_version,
                                 :model_weights, :model_hash, :type, :prompt,
                                 :steps, :cfg_scale, :sampler,
                                 :height, :width, :seed, :png_info)"""
    try:
        cur = conn.cursor()
        meta_values = get_meta_db_values(path, png);
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
        log.error("failed to insert new png into db, transaction rollback:\n" % e)
        conn.rollback()


if __name__ == '__main__':
    init()
    args = args_parse()
    start_time = time.time()
    log.info("starting ...")
    for f in args.infile:
        log.info("processing [file_arg: \"%s\"] ..." % f)
        #pathlist = expandpath(f) #Path().glob(f)
        pathlist = [Path(p) for p in glob(str(Path(f).expanduser()))]
        #log.debug("pathlist: %s" % pathlist)
        #pp = PrettyPrinter(indent=2, width=120)
        for path in pathlist:
            path_start_time = time.time()
            path_str = str(path)
            log.info("processing [file: \"%s\"] ..." % path_str)
            png = Image.open(path_str)
            png.load() # needed to get for .png EXIF data
            #pp.pprint(meta)
            #print(png.info)
            db_insert_png(path, png)
            #except Exception:
            #    log.errro("returning ...")
            #    break
            log.info("finished processing file [exec_time: %s, file_path: \"%s\"]" % (time.time() - path_start_time, path_str))
    log.info("finished processing file_arg [exec_time: %s, file_arg: \"%s\"]" % (time.time() - start_time, f))
