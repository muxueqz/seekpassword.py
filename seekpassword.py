#!/usr/bin/env python3
# coding=utf8
# SeekPassword CLI Version.
# Author: muxueqz(muxueqz.top)

import sys
import hmac

STR1 = "snow".encode("utf8")
STR2 = "kise".encode("utf8")
STR3 = "sunlovesnow1990090127xykab"


def huami(password, key):
    """计算花密密码
    """
    # 得到md5one, md5two, md5three
    # hmac.new(key, msg)
    md5one = hmac.new(key, password, "md5").hexdigest()
    md5two = hmac.new(STR1, md5one.encode("utf8"), "md5").hexdigest()
    md5three = hmac.new(STR2, md5one.encode("utf8"), "md5").hexdigest()
    # 转换大小写
    rule = md5three
    source = list(md5two)
    for i in range(0, 32):
        if rule[i] in STR3:
            source[i] = source[i].upper()
    #code32 = ''.join(source)
    #保证密码首字母为字母---why?
    if source[0].isdigit():
        code16 = "K" + "".join(source[1:16])
    else:
        code16 = "".join(source[0:16])
    return code16, source

lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
punctuation = ",.:;!?"
number = "0123456789"
alphabet = lower + upper + number + punctuation

def get_map_index(sub_hash):
    count = 0
    r = []
    for c in sub_hash:
      count = (count + ord(c)) % len(alphabet)
      r.append(count)
    return r

def seek_password(hash):
  # generate alphabet
  # try to generate password
  for i in range(len(hash) - 10):
    sub_hash = list(hash[i:i + 10])
    map_index = get_map_index(sub_hash)

    sk_pwd = [alphabet[i] for i in map_index]


    # validate password
    match = set()
    match_list =  (lower, upper, number, punctuation)
    for i in sk_pwd:
        for m in range(len(match_list)):
            if i in match_list[m]:
                match.add(m)
    if len(match) == 4:
        return ("".join(sk_pwd))

  return ""

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('key', type=str)
    parser.add_argument('password', type=str)

    args = parser.parse_args()
    key = args.key
    password = args.password
    if password == '-':
        password = sys.stdin.read()

    _, huami_result = huami(password.encode('utf8'),
        key.encode('utf8'))
    print(seek_password(huami_result))
