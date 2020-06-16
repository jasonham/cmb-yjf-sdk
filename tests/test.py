#!/usr/bin/env python
# coding: utf-8

import unittest
from cmb_yjf import CmbYjfPay


class CmbYjfPayTestCase(unittest.TestCase):
    def setUp(self):
        self.DES_key = '1234qwer'
        self.plan_test = {
            "depart": "A05",
            "fee_title": "康桥教育培训费",
            "sum_amt": "3700.98",
            "sum_cnt": "2",
            "begin_date": "20200522",
            "end_date": "20200630",
            "detail": ["kqjy202006070001~^陈同学~^001~^三年级~^二班~^2020学期费用~^学费1000元，餐费500元~^1500~^陈家长~^13818977889~^","kqjy202006070004~^张同~^001~^四年级~^二班~^~^~^2200.98~^~^~^"]
        }
        self.DES_result = "TJ91AmUS6VeYQXPBCHkG4RYhXNBl2gttcj7GVJhm9HKYQXPBCHkG4Uotc+0tEceuOfAURBwCdN8wLs8uAZMSTk49seSCvfT4mLgyE8TMdQYMWFpjAfOmqmiZAcJTY31cDuROqZ3U8b32xBcY3X8n0qWt3aiElavJH2weWlChuB6RqsuJ/hu6IszPLS2fjlDOQPEdLhBb/UWKe4WcKkDeMV1ngEYpBKCy6V6Ev4wNAxBmygogANrvVMep8c85LcCDAsbzpIUUzB5PG2ae1FRI6wIjya7dA1aYRKRzDc49iU+gIdbtwdJ+gr2rHAlGRSaJrzA+SNAe8C/5L826BKfCoK97faRS187gr+Luy863MYk3v5E5rQpVSTrWUSSmaLlG9WivmtMeSneima6JtwRsCw2yf2oye6QzuM75vuJB/KRrEkthMHi8Mhu/oTIIdAhHiO44g6XZZn/HjjW7ifVJypXtxxHG3+e1Z6WAgHpDOm0="
        self.md5_result = "c9cd2931152f270697081aac82c5b48c"

        self.cmb = CmbYjfPay(depart='A05', des_encrypt_key=self.DES_key, des_decrypt_key=self.DES_key)

    def tearDown(self):
        pass

    def test_DES_encryption(self):
        ciphertext = self.cmb.des_encode_data(self.plan_test)
        self.assertEqual(ciphertext, self.DES_result)

    def test_MD5_encryption(self):
        ciphertext = self.cmb.des_encode_data(self.plan_test)
        md5 = self.cmb.md5_32bit_lower_case(ciphertext)
        self.assertEqual(md5, self.md5_result)

    def test_DES_decrypt(self):
        decode_obj = self.cmb.des_decode_date(self.DES_result)
        self.assertEqual(self.plan_test, decode_obj)

    def test_detail_format(self):
        detail_list = [
            ['xx101', '张敏', '001', '三年级', '二班', '学杂费', '统一收费20.00元', '20.00', '张三', '15066666666'],
            ['xx102', '李莉', '002', '三年级', '二班', '课间餐费', '统一收费30.00元/月', '30.00', '李四', '15088888888']
        ]
        result = [
            "xx101~^张敏~^001~^三年级~^二班~^学杂费~^统一收费20.00元~^20.00~^张三~^15066666666~^",
            "xx102~^李莉~^002~^三年级~^二班~^课间餐费~^统一收费30.00元/月~^30.00~^李四~^15088888888~^"
        ]
        self.assertEqual(result, self.cmb._format_deatil(detail_list))

    def test_import(self):
        from cmb_yjf import CmbYjfPay
        detail = [
            ['xx103', '张敏', '001', '三年级', '二班', '学杂费', '统一收费20.00元', '20.00', '张三', '15066666666'],
            ['xx104', '李莉', '002', '三年级', '二班', '课间餐费', '统一收费30.00元/月', '30.00', '李四','15088888888']
        ]
        from datetime import date
        begin_date = date(2020, 05, 22)
        end_date = date(2020, 06, 30)
        fee_title = '康桥教育培训费'
        DES_key = '1234qwer'
        cmb = CmbYjfPay(depart='A05', des_encrypt_key=DES_key, des_decrypt_key=DES_key)
        import_data = cmb.api('cmbpay.import')
        result = import_data(detail=detail, begin_date=begin_date, end_date=end_date, fee_title=fee_title)
        print(result)

    def test_query_all(self):
        fee_act_id = '18'
        query_all = self.cmb.api('cmbpay.query')
        result = query_all(fee_act_id=fee_act_id)
        print(result)

    def test_query_one(self):
        fee_act_id = '18'
        fee_id = '3475eff0be6dd968e966d1a5ac8cb7d3'
        query_one = self.cmb.api('cmbpay.query')
        result = query_one(fee_act_id=fee_act_id, fee_id=fee_id)
        print(result)

    def test_delete(self):
        delete_list = [
            '06a5c7b9903616994ad4a43482aff3cf',
            'bede867e42c7c8afca28795464118509'
        ]
        delete = self.cmb.api('cmbpay.delete')
        result = delete(delete_list=delete_list)
        print(result)

    def test_query_bank_all(self):
        fee_act_id = '10'
        query_one = self.cmb.api('cmbpay.query_bank')
        pag_siz = 100
        pag_nbr = 1
        result = query_one(fee_act_id=fee_act_id, pag_siz=pag_siz, pag_nbr=pag_nbr)
        print(result)

    def test_query_bank_one(self):
        fee_act_id = '10'
        fee_id = '68001f2b1677903fa54f51f93068dbe6'
        query_one = self.cmb.api('cmbpay.query_bank')
        result = query_one(fee_act_id=fee_act_id, fee_id=fee_id)
        print(result)


if __name__ == '__main__':
    # unittest.main(warnings='ignore')
    unittest.main()

