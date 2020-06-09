#!/usr/bin/env python
# coding: utf-8

import unittest
from cmb_yjf import CmbYjfPay


class CmbYjfPayTestCase(unittest.TestCase):
    def setUp(self):
        self.DES_key = '1234qwer'
        self.plan_test = {
            "depart": "A03",
            "fee_title": "康桥教育培训费",
            "sum_amt": "3700.98",
            "sum_cnt": "2",
            "begin_date": "20200522",
            "end_date": "20200630",
            "detail": ["kqjy202006070001~^陈同学~^001~^三年级~^二班~^2020学期费用~^学费1000元，餐费500元~^1500~^陈家长~^13818977889~^","kqjy202006070004~^张同~^001~^四年级~^二班~^~^~^2200.98~^~^~^"]
        }
        self.DES_result = "TJ91AmUS6VeYQXPBCHkG4RYhXNBl2gttcj7GVJhm9HKYQXPBCHkG4Uotc+0tEceuOfAURBwCdN8wLs8uAZMSTk49seSCvfT4mLgyE8TMdQYMWFpjAfOmqmiZAcJTY31cDuROqZ3U8b32xBcY3X8n0qWt3aiElavJH2weWlChuB6RqsuJ/hu6IszPLS2fjlDOQPEdLhBb/UWKe4WcKkDeMV1ngEYpBKCy6V6Ev4wNAxBmygogANrvVMep8c85LcCDAsbzpIUUzB5PG2ae1FRI6wIjya7dA1aYRKRzDc49iU+gIdbtwdJ+gr2rHAlGRSaJrzA+SNAe8C/5L826BKfCoK97faRS187gr+Luy863MYk3v5E5rQpVSTrWUSSmaLlG9WivmtMeSneima6JtwRsCw2yf2oye6QzuM75vuJB/KRrEkthMHi8Mhu/oTIIdAhHzfEA1LGWderHjjW7ifVJypXtxxHG3+e1Z6WAgHpDOm0="
        self.md5_result = "1d63ee856d8a64d75a368f7cf7fa162b"

        self.cmb = CmbYjfPay(depart='A05', des_key=self.DES_key)


    def tearDown(self):
        pass

    def test_DES_encryption(self):
        ciphertext = self.cmb.des_encode_data(self.plan_test)
        self.assertEqual(ciphertext, self.DES_result)

    def test_MD5_encryption(self):
        ciphertext = self.cmb.des_encode_data(self.plan_test)
        md5 = self.cmb.md5_32bit_lower_case(ciphertext)
        self.assertEqual(md5, self.md5_result)


if __name__ == '__main__':
    unittest.main(warnings='ignore')
