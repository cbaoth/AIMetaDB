#!/usr/bin/env python3

# https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/
# pip install pillow
# https://pillow.readthedocs.io/en/stable/reference
# https://pypi.org/project/ImageHash/
# pip install "thefuzz[speedup]"
# https://github.com/seatgeek/thefuzz
# https://github.com/AUTOMATIC1111/stable-diffusion-webui-tokenizer

# TODO
# add templates to db

import argparse
from datetime import datetime
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
from pprint import PrettyPrinter
#import imagehash
from enum import Enum

DEFAULT_FNAME_PATTERN = '{file_ctime_iso}_{model_hash_short}-{seed}-{image_hash_short}_[{cfg_scale}@{steps}#{sampler}#{model}]'
DEFAULT_DB_FILE = str(Path.home()) + '/ai_meta.db'
DEFAULT_LOG_FILE = str(Path.home()) + '/ai_meta.log'
DEFAULT_LOGLEVEL_FILE = 'INFO'
DEFAULT_LOGLEVEL_CL = 'WARNING'

class Mode(Enum):
    UPDATEDB = 1
    MATCHDB = 2
    RENAME = 3
    TOJSON = 4
    TOCSV = 5
    TOKEYVALUE = 6

META_TYPE_KEY = 'meta_type'
class MetaType(Enum):
    INVOKEAI = 1
    A1111 = 2

log = logging
args = None
conn = None
mode = Mode.MATCHDB

pp = PrettyPrinter(4, 120)


# raised when there's an error reading or processing meta data
class InvalidMeta(Exception):
    pass


# parse and return command line arguments
def args_init():
    parser = argparse.ArgumentParser(description='AIMetaDB - A Invoke-AI PNG file metadata processor')
    parser.add_argument('infile', type=Path, nargs='+',
                        help='One or more file names, directories, or glob patterns')
    parser.add_argument('--mode', type=str.upper, default='UPDATEDB',
                        choices=['UPDATEDB', 'MATCHDB', 'RENAME', 'TOJSON', 'TOCSV', 'TOKEYVALUE'],
                        help='Processing mode [UPDATEDB: add file meta to db, MATCHDB: match file meta with db, RENAME: reame files by metadata')
    parser.add_argument('--similarity_min', type=int, default=0,
                        help='Filter matchdb mode results based on similarity >= X [default: 0]')
    parser.add_argument('--sort_matches', action='store_true',
                        help='Sort results by similartiy (desc) grouped by infile (WARNING: memory heavy when processing large result sets)')
    parser.add_argument('--fname_pattern', type=str, default=DEFAULT_FNAME_PATTERN,
                        help='File renaming pattern for RENAME mode [default: %s]' % DEFAULT_FNAME_PATTERN)  # todo document available fields
    parser.add_argument('--no-act', action='store_true',
                        help='Only print what would be done without changing anything (mode = RENAME only)')
    parser.add_argument('--include_png_info', action='store_true',
                        help='Include full png_info when printing meta (mode = TOJSON|TOKEYVALUE only)')
    parser.add_argument('--recursive', action='store_true',
                        help='Process directories and ** glob patterns recursively')
    parser.add_argument('--dbfile', type=str, default=DEFAULT_DB_FILE,
                        help='DB file location [default: %s]' % DEFAULT_DB_FILE)
    parser.add_argument('--logfile', type=str, default=DEFAULT_LOG_FILE,
                        help='Log file location [default: %s]' % DEFAULT_LOG_FILE)
    parser.add_argument('--loglevel_file', type=str.upper, default=DEFAULT_LOGLEVEL_FILE,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level for log file [default: %s], loglevel_cl will overwrite if higher' % DEFAULT_LOGLEVEL_FILE)
    parser.add_argument('--loglevel_cl', type=str.upper, default=DEFAULT_LOGLEVEL_CL,
                        choices=['NONE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level for command line output [default: %s], NONE for quiet mode (results only)' % DEFAULT_LOGLEVEL_CL)
    global args, mode
    args = parser.parse_args()
    mode = Mode[args.mode]


# initialize logger
def log_init(logfile_path, level_file, level_cl):
    # TODO check if we can't just add a separate file handler and selt base consig to DEBUG
    # cl level can't be higher than core log level
    if (level_cl != 'NONE' and (logging.getLevelName(level_cl) < logging.getLevelName(level_file))):
        level_file = level_cl
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
                                meta_type int,
                                file_name text,
                                app_id text,
                                app_version text,
                                model text,
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
                                file_ctime date,
                                file_mtime date,
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

        # migrate
        #cur.execute('alter table meta add column meta_type integer')
        #cur.execute('alter table meta add column file_ctime date')
        #cur.execute('alter table meta add column file_mtime date')
        #cur.execute('update meta set meta_type = 1')
        #conn.commit()

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


def a1111_meta_to_dict_to_json(params):
    #[p, s] = re.split(r'\n(Steps: )', params)   # FIXME comple all regex globally
    #try:
    result = {}
    is_prompt = True
    last_key = ""
    for l in re.split(r'\n', params):
        # first line is always prompt (w/o prefix)
        if (is_prompt):
            result['prompt'] = l
            is_prompt = False
            continue
        # at least 4 of the known core attributes in current line? (crude check)
        if (len(re.findall(r'(steps|sampler|size|seed|model hash|cfg scale): ', l, flags=re.IGNORECASE)) >= 4):
            # convert to dict
            result.update(dict(map(lambda e: [e[0].lower().strip().replace(' ', '_'), e[1].strip()], re.findall(r'[, ]*([^:]+): ([^,]+)?', l))))
        elif (re.match(r'^[\w -]+: ', l)): # TODO improve, multi-line template might have lines starting like this
            # add to dict
            key = re.sub(r'^([^:]+):.*', r'\1', l).lower().strip().replace(' ', '_')
            val = re.sub(r'^[^:]+: *(.*)', r'\1', l).strip()
            result[key] = val
            last_key = key
        else:
            # continue multi-line field (append)
            if (last_key == ""):
                log.warning("found value without key, skipping ... [%s]" % val)
                continue
            result[last_key] += " " + l.strip()

    # does this look like a1111 meta? (crude check)
    re_exp_find = r'([{}|]|__)'
    re_exp_warn = r'(.{6}(?:[{}|]|__).{6}|(?:[{}|]|__).{6}|.{6}(?:[{}|]|__)|(?:[{}|]|__))'
    if (len(result) <= 0 or ('prompt' not in result) or ('steps' not in result)):
        raise InvalidMeta("Unable to process presumed A1111 meta:\n%s\n-> %s" % (params, result))
    if (len(re.findall(re_exp_find, result['prompt'])) > 0):
        log.warning('Prompt seems to contain un-evaluated expressions, please check! %s' % re.findall(re_exp_warn, result['prompt']))
    if (re.match(re_exp_find, result['negative_prompt'])):
        log.warning('Prompt seems to contain un-evaluated expressions, please check! %s' % str(re.findall(re_exp_warn, result['negative_prompt'])))
    [result['width'], result['height']] = result['size'].split('x')
    result['app_id'] = 'AUTOMATIC1111/stable-diffusion-webui'
    result['app_version'] = None # info not provided
    result['type'] = None  # info not provided (t2i/i2i)
    result[META_TYPE_KEY] = MetaType.A1111.value
    return result
    #nSteps: 20, Sampler: Euler a, CFG scale: 8.5, Seed: 2518596816, Size: 512x768, Model hash: 7dd744682a'


def get_meta(path, png, image_hash, png_meta_as_dict=False, include_png_info=False):
    file_name = os.path.basename(path)
    try:
        meta_dict = png.info
        if ('sd-metadata' in meta_dict):  # invoke-ai
            # parse sd-metadata (json) string to dict
            sd_meta = json.loads(meta_dict['sd-metadata'])
            sd_meta[META_TYPE_KEY] = MetaType.INVOKEAI.value
            meta_dict['sd-metadata'] = sd_meta  # overwrite json-string with dict
        elif ('parameters' in meta_dict):   # a1111
            sd_meta = a1111_meta_to_dict_to_json(meta_dict['parameters'])
        else:
            raise InvalidMeta("No known meta found in [file_path:\"%s\"]" % path)
    except KeyError as e:
        log.warning("no known meta found in [file_path: %s]" % path)
        raise InvalidMeta(e)
    png_info = meta_dict if png_meta_as_dict else json.dumps(meta_dict)
    m = sd_meta.copy()
    if sd_meta[META_TYPE_KEY] == MetaType.INVOKEAI.value:
        # TODO add all fields (update m with flattened keys)
        result = {"meta_type": sd_meta[META_TYPE_KEY],
                  "file_name": file_name,
                  "app_id": sd_meta['app_id'],
                  "app_version": sd_meta['app_version'],
                  "model": sd_meta['model_weights'],
                  "model_hash": sd_meta['model_hash'],
                  "type": sd_meta['image']['type'],
                  "prompt": sd_meta['image']['prompt'][0]['prompt'],
                  #"negative_prompt": sd_meta['image']['prompt'][0]['negative_prompt'],
                  "steps": sd_meta['image']['steps'],
                  "cfg_scale": sd_meta['image']['cfg_scale'],
                  "sampler": sd_meta['image']['sampler'],
                  "height": sd_meta['image']['height'],
                  "width": sd_meta['image']['width'],
                  "seed": sd_meta['image']['seed'],
                  "image_hash": image_hash,
                  "file_ctime_iso": timestamp_to_iso(os.path.getctime(path)),
                  "file_mtime_iso": timestamp_to_iso(os.path.getmtime(path))}
    else:  # A1111
        m.update({"meta_type": sd_meta[META_TYPE_KEY],
                  "file_name": file_name,
                  "image_hash": image_hash,
                  "file_ctime": os.path.getctime(path),
                  "file_mtime": os.path.getmtime(path),
                  "file_ctime_iso": timestamp_to_iso(os.path.getctime(path)),
                  "file_mtime_iso": timestamp_to_iso(os.path.getmtime(path))})
        result = m;
    if include_png_info:
        result['png_info'] = png_info
    log.debug('meta data extracted: %s' % pp.pformat(result))
    return result


def db_get_meta_file_name_by_hash(image_hash):
    sql_select = """SELECT file_name FROM meta WHERE image_hash = :image_hash;"""
    cur = conn.cursor()
    cur.execute(sql_select, {"image_hash": image_hash})
    row = cur.fetchone()
    return None if row is None else row[0]


def db_insert_meta(path, png, image_hash):
    file_name = os.path.basename(path)
    log.info("inserting meta in db for [image_hash: %s, path: \"%s\"" % (image_hash, str(path)))
    sql_insert_meta = """INSERT INTO meta (meta_type, file_name, app_id, app_version,
                                           model, model_hash, type, prompt,
                                           steps, cfg_scale, sampler,
                                           height, width, seed, png_info,
                                           image_hash, file_ctime, file_mtime)
                         VALUES (:meta_type, :file_name, :app_id, :app_version,
                                 :model, :model_hash, :type, :prompt,
                                 :steps, :cfg_scale, :sampler,
                                 :height, :width, :seed, :png_info,
                                 :image_hash, :file_ctime, :file_mtime);"""
    try:
        cur = conn.cursor()
        meta_values = get_meta(path, png, image_hash);
        log.debug("db INSERT into meta: %s" % str(meta_values))
        cur.execute(sql_insert_meta, meta_values)
        conn.commit()
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return;
    except sqlite3.IntegrityError:
        res = cur.execute("SELECT file_name FROM meta WHERE image_hash = ?", (image_hash,))
        # todo: compare file names
        row = res.fetchone()
        if (row[0] == file_name):
            log.info("skipping existing entry: [hash_hase: %s, file_name_old: \"%s\", file_name_new: \"%s\"]" % (image_hash, row[0], file_name))
        else:
            log.info("skipping existing entry: [hash_hase: %s, file_name: \"%s\"]" % (image_hash, file_name))
        log.debug("failed to insert duplicate png into db, existing record: %s" % str(dict((row))))
        conn.rollback()
    except Error as e:
        log.error("failed to insert new meta into db, transaction rollback: %s\n" % e)
        conn.rollback()


def db_update_meta(path, png, image_hash):
    log.info("updating meta in db for [image_hash: %s, path: \"%s\"" % (image_hash, str(path)))
    sql_update_meta = """UPDATE meta
                         SET meta_type = :meta_type, file_name = :file_name, app_id = :app_id, app_version = :app_version,
                             model = :model, model_hash = :model_hash, type = :type, prompt = :prompt,
                             steps = :steps, cfg_scale = :cfg_scale, sampler = :sampler,
                             height = :height, width = :width, seed = :seed, png_info = :png_info,
                             file_ctime = file_ctime, file_mtime = file_mtime
                         WHERE image_hash = :image_hash;"""
    try:
        cur = conn.cursor()
        meta_values = get_meta(path, png, image_hash);
        log.debug("db UPDATE into meta: %s" % str(meta_values))
        cur.execute(sql_update_meta, meta_values)
        conn.commit()
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return;
    except Error as e:
        log.error("failed to update existing meta in db, transaction rollback:\n" % e)
        conn.rollback()


def db_update_or_create_meta(path, png, image_hash):
    file_name_org = db_get_meta_file_name_by_hash(image_hash)
    if (file_name_org == None):  # not found?
        db_insert_meta(path, png, image_hash)
    else:  # record with same image hash found
        if (file_name_org != os.path.basename(path)):
            log.debug("updating meta, file_name will change from [\"%s\"] to [\"%s\"]" %
            (file_name_org, os.path.basename(path)))
        db_update_meta(path, png, image_hash)


def print_column_headrs():
    # TODO support custom pattern
    print('in_file_idx | db_file_idx | file_source | similarity | steps | cfg_scale | sampler | height | width | seed | model_hash | model | meta_type | type | image_hash | file_name | file_ctime | file_mtime | app_id | app_version | prompt')


def sanitize_value(val, escape_quotes=True):
    val_str = str(val)
    # escape double-quotes " in prompt (promt will be within " on output)
    # replace all newline with spaces
    result = re.sub(r'(["\\])', r'\\\1', val_str) if escape_quotes else val_str
    result = re.sub(r'\r?\n', r' ', result).strip()
    return result


def timestamp_to_iso(ts):
    #try:
    return datetime.fromtimestamp(ts).isoformat()
    #except:
    #    log.debug("Unable to convert timestamp [ts=%s] to iso datetime." % ts)
    #    return ""

# convert meta dict to output tuple
def meta_to_output_tuple(dict):
    # TODO support custom patterns
    prompt_esc = re.sub(r'\r?\n', r' ', re.sub(r'(["\\])', r'\\\1', dict['prompt']).strip())
    return (dict['steps'], dict['cfg_scale'], dict['sampler'], dict['height'], dict['width'], dict['seed'],
            dict['model_hash'], dict['model'], dict[META_TYPE_KEY], dict['type'], dict['image_hash'],
            dict['file_ctime_iso'], dict['file_mtime_iso'], dict['file_name'],
            dict['app_id'], dict['app_version'], sanitize_value(prompt_esc))


def db_match(path, png, image_hash, idx, sort=False):
    result = []
    print_pattern = "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | \"%s\" | \"%s\""
    try:
        file_meta = get_meta(path, png, image_hash)
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return
    file_meta['prompt'] = sanitize_value(file_meta['prompt'])
    sql_select = """SELECT steps, cfg_scale, sampler, height, width, seed, model_hash, model, meta_type, type, image_hash, file_name, file_ctime, file_mtime, app_id, app_version, prompt FROM meta;"""
    cur = conn.cursor()
    cur.execute(sql_select)
    result_set = cur.fetchall()
    log.debug("meta for file [\"%s\"]:\n%s" % (path, file_meta))
    # TODO allow file output (nice to have, redirect possible)
    file_printed = False
    i = 1
    for row in result_set:
        row_meta = dict(row)
        row_meta['prompt'] = sanitize_value(row_meta['prompt'])
        row_meta['file_ctime_iso'] = timestamp_to_iso(row_meta['file_ctime'])
        row_meta['file_mtime_iso'] = timestamp_to_iso(row_meta['file_mtime'])
        #print("-----> %s\n-----> %s" % (row_meta['prompt'], file_meta['prompt']))
        similarity = fuzz.token_sort_ratio(row_meta['prompt'], file_meta['prompt'])
        if (file_meta['image_hash'] == row_meta['image_hash']):
            log.debug("skipping db meta with same image_hash as given file")
            continue
        if (similarity >= args.similarity_min):
            if (not file_printed):  # print current file in first iteration (not at all if no matches were found)
                file_printed = True
                print(file_meta)
                t = (idx, i, 'file', 100) + meta_to_output_tuple(file_meta)
                if (sort):
                    result.append(t)
                else:
                    print(print_pattern % t)
            t = (idx, i, 'db', similarity) + meta_to_output_tuple(row_meta)
            if (sort):
                result.append(t)
            else:
                print(print_pattern % t)
        i = i+1
    cur.close()
    if (sort):
        for r in sorted(result, key=lambda x: (x[0], -x[3])):
            print(print_pattern % r)


def rename_file(file_path, png, image_hash):
    # FIXME split path an fname, currently filename must be first (path is included)
    try:
        meta = get_meta(file_path, png, image_hash)
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % file_path)
        log.debug(e)
        return
    path = os.path.split(file_path)[0]
    [meta['file_name_noext'], meta['file_ext']] = os.path.splitext(meta['file_name'])
    meta['model_hash_short'] = meta['model_hash'][0:10]
    meta['image_hash_short'] = meta['image_hash'][0:10]
    meta['file_ctime_iso'] = meta['file_ctime_iso'].replace(':', '') # strip specials
    meta['file_mtime_iso'] = meta['file_mtime_iso'].replace(':', '') # strip specials
    out_file_name = args.fname_pattern.format(**meta) + meta['file_ext']
    out_file_name_sanitized = re.sub(r'[^,.;\[\]{}&%#@+\w-]', '_', out_file_name)
    out_path = os.path.normpath(os.path.join(path, out_file_name_sanitized))
    if (os.path.normpath(file_path) == out_path):
        log.warning("Outfile identical to infile name [%s], skipping ..." % out_path)
    elif (Path(out_path).exists()):
        log.warning("File with same name exists [%s], skipping ..." % out_path)
        # TODO add --force-overwirte option
    elif (args.no_act):
        msg = "Would rename: [\"%s\"] -> [\"%s\"]" % (file_path, out_path)
        log.info(msg)
        print(msg)
    else:
        msg = "Renaming: [\"%s\"] -> [\"%s\"]" % (file_path, out_path)
        log.info(msg)
        print(msg)
        os.rename(file_path, out_path)


def print_file_meta_json(path, png, image_hash, include_png_info=False):
    try:
        file_meta = get_meta(path, png, image_hash, png_meta_as_dict=True, include_png_info=include_png_info)
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return
    print(json.dumps(file_meta, indent=4))


def print_file_meta_csv(path, png, image_hash):
    print_pattern = "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | \"%s\" | \"%s\""
    try:
        file_meta = get_meta(path, png, image_hash)
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return
    file_meta['prompt'] = sanitize_value(file_meta['prompt'])
    print(print_pattern % meta_to_output_tuple(file_meta))


def print_file_meta_keyvalue(path, png, image_hash, include_png_info=False):
    try:
        file_meta = get_meta(path, png, image_hash, include_png_info=include_png_info)
        #file_meta.pop('png_meta')  # don't print png_meta
    except InvalidMeta as e:
        log.warning("Unable to read meta from [file_path: \"%s\"], skipping .." % path)
        log.debug(e)
        return
    for key, val in file_meta.items():
        print("%s: %s" % (key, sanitize_value(val)))


def process_file(file_path, idx):
    try:
        png = Image.open(str(file_path) )
        png.load() # needed to get for .png EXIF data
    except (AttributeError, IsADirectoryError) as e:  # directory or other type?
        log.warning("Not a file, skipping: %s" % file_path)
        log.debug(str(e))
        return
    except UnidentifiedImageError as e:
        log.warning("Not a valid image file, skipping: %s" % file_path)
        log.debug(str(e))
        return
    except OSError as e:
        log.warning("IO error while reading file, skipping: %s" % file_path)
        log.debug(str(e))
        return
    try:
        image_hash = file_hash(file_path) # TODO optimize: consider moving to later stage, may not be needed in all cases
    except OSError as e:
        log.warning("I/O error while calculate image hash for file [\"%s\"], skipping ...")
        log.debug(e)
        return
    if (mode == Mode.UPDATEDB):
        db_update_or_create_meta(file_path, png, image_hash)
    elif (mode == Mode.MATCHDB):
        print_column_headrs()
        db_match(file_path, png, image_hash, idx, args.sort_matches)
    elif (mode == Mode.RENAME):
        rename_file(file_path, png, image_hash)
    elif (mode == Mode.TOJSON):
        print_file_meta_json(file_path, png, image_hash, include_png_info=args.include_png_info)
    elif (mode == Mode.TOCSV):
        print_file_meta_csv(file_path, png, image_hash)
    elif (mode == Mode.TOKEYVALUE):
        print_file_meta_keyvalue(file_path, png, image_hash, include_png_info=args.include_png_info)
    else:  # should never happen
        log.error("Unknown mode: %s" % mode)
        sys.exit(1)


def process_paths():
    start_time_proc = time.time()
    log.info("starting [mode=%s] ..." % args.mode)
    idx = 1
    for f in args.infile:
        start_time_path_arg = time.time()
        log.debug("processing [file_arg: \"%s\"] ..." % f)
        # single file or glob expansion
        # FIXME currently can't handle "./" recursion (maybe others too)
        file_paths = [f] if (f.exists() and f.is_file()) else [Path(p) for p in glob(str(f.expanduser()), recursive=args.recursive)]
        if (len(file_paths) <= 0):
            log.warning("no file(s) found for infile pattern [\"%s\"], skipping ..." % f)
            continue
        for file_path in file_paths:
            start_time_file = time.time()
            log.info("processing [#%s, file: \"%s\"] ..." % (idx, file_path))
            process_file(file_path, idx)
            log.debug("finished processing file [#%s, exec_time: %ssec, file_path: \"%s\"]" %
                      (idx, round(time.time() - start_time_file, 3), file_path))
            idx = idx + 1
        log.debug("finished processing file_arg [exec_time: %ssec, file_arg: \"%s\"]" %
                  (round(time.time() - start_time_path_arg, 3), f))
    log.info("finished [mode=%s, exec_time: %ssec]!" %
             (mode.name, round(time.time() - start_time_proc, 3)))


if __name__ == '__main__':
    init()
    start_time = time.time()
    # TODO handle somewhere else
    if (mode == Mode.TOCSV):
        print('steps | cfg_scale | sampler | height | width | seed | model_hash | model | meta_type | type | image_hash | file_name | file_ctime | file_mtime | app_id | app_version | prompt')
    process_paths()
