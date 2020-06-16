#!/usr/bin/env python
# coding: utf-8

"""
    招商银行云缴费
"""
import json
import pyDes
import base64
from zeep import Client

from datetime import date
from functools import partial

import hashlib
from Cryptodome.Hash import SHA, SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

from .exceptions import CMBYJFException


class CmbYjfBasePay:
    # @property
    # def opr_usr(self):
    #     """用户ID"""
    #     return self._opr_usr
    #
    # @property
    # def merch_id(self):
    #     """商户编号"""
    #     return self._merch_id
    #
    # @property
    # def sign_type(self):
    #     return self._sign_type
    #
    # @property
    # def app_private_key(self):
    #     """签名用"""
    #     return self._app_private_key
    #
    # @property
    # def cmb_public_key(self):
    #     """验证签名用"""
    #     return self._cmb_public_key
    @property
    def depart(self):
        """学校编号"""
        return self._depart

    @property
    def des_encrypt_key(self):
        """DES 加密 用"""
        return self._des_encrypt_key

    @property
    def des_decrypt_key(self):
        """DES 解密 用"""
        return self._des_decrypt_key

    def __init__(
            self,
            # opr_usr,
            # merch_id,
            # app_private_key_string=None,
            # cmb_public_key_string=None,
            depart=None,
            des_encrypt_key=None,
            des_decrypt_key=None,
            debug=False
    ):
        """
        初始化:

        """
        # self._opr_usr = str(opr_usr)
        # self._merch_id = str(merch_id)
        # self._app_private_key_string = app_private_key_string
        # self._cmb_public_key_string = cmb_public_key_string
        self._depart = str(depart)
        self._des_encrypt_key_string = des_encrypt_key
        self._des_decrypt_key_string = des_decrypt_key

        self._app_private_key = None
        self._cmb_public_key = None
        self._des_encrypt_key = None
        self._des_decrypt_key = None

        if debug:
            self._gateway = "http://www.chinwooaie.com:2300/cmbyjf/webservice/cmbyjf?wsdl"
        else:
            self._gateway = "http://www.chinwooaie.com:2300/cmbyjf/webservice/cmbyjf?wsdl"

        # load key file immediately
        self._load_key()

    def _load_key(self):
        # # load private key
        # content = self._app_private_key_string
        # self._app_private_key = RSA.importKey(content)
        #
        # # load public key
        # content = self._cmbpay_public_key_string
        # self._cmb_public_key = RSA.importKey(content)

        # load Des key
        content = self._des_encrypt_key_string
        self._des_encrypt_key = content

        content = self._des_decrypt_key_string
        self._des_decrypt_key = content

    def _des_encode(self, plaintext):
        """DES 加密"""
        key = self.des_encrypt_key
        des = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
        encrypt_str = des.encrypt(plaintext)
        return base64.b64encode(encrypt_str)

    def _des_decode(self, cipher_text):
        """DES 解密"""
        key = self.des_decrypt_key
        des = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
        decode_str = base64.b64decode(cipher_text)
        return des.decrypt(decode_str)


    # def _sign(self, unsigned_string):
    #     """
    #     通过如下方法调试签名
    #     方法1
    #         key = rsa.PrivateKey.load_pkcs1(open(self._app_private_key_string).read())
    #         sign = rsa.sign(unsigned_string.encode(), key, "SHA-1")
    #         # base64 编码，转换为unicode表示并移除回车
    #         sign = base64.encodebytes(sign).decode().replace("\n", "")
    #     方法2
    #         key = RSA.importKey(open(self._app_private_key_string).read())
    #         signer = PKCS1_v1_5.new(key)
    #         signature = signer.sign(SHA.new(unsigned_string.encode()))
    #         # base64 编码，转换为unicode表示并移除回车
    #         sign = base64.encodebytes(signature).decode().replace("\n", "")
    #     方法3
    #         echo "abc" | openssl sha1 -sign cmbpay.key | openssl base64
    #     """
    #     # 开始计算签名
    #     key = self.app_private_key
    #     signer = PKCS1_v1_5.new(key)
    #     signature = signer.sign(SHA256.new(unsigned_string.encode()))
    #     # base64 编码，转换为unicode表示并移除回车
    #     sign = encodebytes(signature).decode().replace("\n", "")
    #     return sign

    # def _sign(self, unsigned_string):
    #     # 开始计算签名  加签
    #     hsobj = hashlib.sha256()
    #     hsobj.update(unsigned_string.encode("utf-8"))
    #     data = hsobj.hexdigest()
    #     key = self.app_private_key
    #     signer = PKCS1_v1_5.new(key)
    #     signature = signer.sign(SHA256.new(data.encode()))
    #     sign = base64.b64encode(signature)
    #     return sign
    #
    # def _verify(self, raw_content, signature):
    #     # 开始计算签名  验签
    #     key = self.cmbpay_public_key
    #     signer = PKCS1_v1_5.new(key)
    #     digest = SHA256.new()
    #     digest.update(raw_content.encode())
    #     return bool(signer.verify(digest, base64.b64decode(signature)))
    #
    # def _ordered_data(self, data):
    #     for k, v in data.items():
    #         if isinstance(v, dict):
    #             # 将字典类型的数据dump出来
    #             data[k] = json.dumps(v, separators=(',', ':'))
    #     return sorted(data.items())

    # def build_body(
    #     self, method, biz_content, return_url=None, notify_url=None, append_auth_token=False
    # ):
    #     data = {
    #         "app_id": self._appid,
    #         "method": method,
    #         "charset": "utf-8",
    #         "sign_type": self._sign_type,
    #         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    #         "version": "1.0",
    #         "biz_content": biz_content
    #     }
    #     if append_auth_token:
    #         data["app_auth_token"] = self.app_auth_token
    #
    #     if return_url is not None:
    #         data["return_url"] = return_url
    #
    #     if method in (
    #         "cmbpay.trade.app.pay", "cmbpay.trade.wap.pay", "cmbpay.trade.page.pay",
    #         "cmbpay.trade.pay", "cmbpay.trade.precreate"
    #     ) and (notify_url or self._app_notify_url):
    #         data["notify_url"] = notify_url or self._app_notify_url
    #
    #     return data

    def build_body(self, data):
        body = {
            'Data': self.des_encode_data(data),
            'Md5': self.md5_32bit_lower_case(self.des_encode_data(data)),
            'depart': self.depart
        }
        # merch_id = data.get('merch_id', False)
        # if merch_id and merch_id == self.merch_id:
        #     body.update({
        #         'Id': self.merch_id
        #     })
        # else:
        #     message = "商户参数（Id）不符，merch_id：{}！={}".format(merch_id, self.merch_id)
        #     raise CMBYJFException(None, message)

        return body

    def des_encode_data(self, data):
        # ordered_items = self._ordered_data(data)
        # raw_string = "&".join("{}={}".format(k, v) for k, v in ordered_items)
        # encode = self._des_encode(raw_string)
        raw_string = json.dumps(data, ensure_ascii=False)
        encode = self._des_encode(raw_string)
        return encode

    def des_decode_date(self, data):
        decode_string = self._des_decode(data)
        decode = json.loads(decode_string)
        return self.unicode_convert(decode)

    def unicode_convert(self, input_data):
        if isinstance(input_data, dict):
            return {self.unicode_convert(key): self.unicode_convert(value) for key, value in input_data.iteritems()}
        elif isinstance(input_data, list):
            return [self.unicode_convert(element) for element in input_data]
        elif isinstance(input_data, unicode):
            return input_data.encode('utf-8')
        else:
            return input_data


    # def sign_data(self, data):
    #     data.pop("sign", None)
    #     # 排序后的字符串
    #     ordered_items = self._ordered_data(data)
    #     raw_string = "&".join("{}={}".format(k, v) for k, v in ordered_items)
    #     return self._sign(raw_string)

    def md5_32bit_lower_case(self, data):
        m = hashlib.md5()
        m.update(data)
        return m.hexdigest()

    # def verify(self, data, signature):
    #     # 排序后的字符串
    #     unsigned_items = self._ordered_data(data)
    #     message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)
    #     return self._verify(message, signature)

    def _format_deatil(self, data_list):
        result = list()
        split = '~^'
        for data in data_list:
            string = ''
            for d in data:
                string += str(d) + split
            result.append(string)
        return result

    def _post_data(self, method, data):
        client = Client(self._gateway)
        deal = {
            "model": method,
            "param": json.dumps(data)
        }
        result = client.service.doDeal(**deal)
        result = json.loads(result)
        if result.get('IsError', True):
            msg = result.get('ErrorMsg', '未知错误')
            print msg

            raise CMBYJFException(None, msg)
        else:
            if self.md5_32bit_lower_case(result.get('Data', '')) != result.get('Md5'):
                raise CMBYJFException(None, '回传未通过校验:{}'.format(result))
            res = self.des_decode_date(result.get('Data'))
            detail = res.pop('detail')
            res.update({
                'detail': self._decode_detail(detail)
            })

        return res

    def _decode_detail(self, detail):
        res = list()
        for data in detail:
            res.append(data.split('~^'))
        return res



    def api(self, api_name, **kwargs):
        """
        cmbpay.api("cmbpay.trade.page.pay", **kwargs) ==> cmbpay.api_cmbpay_trade_page_pay(**kwargs)
        """
        api_name = api_name.replace(".", "_")
        key = "api_" + api_name
        if hasattr(self, key):
            return getattr(self, key)
        raise AttributeError("Unknown attribute" + api_name)

    def api_cmbpay_import(self, detail, begin_date, end_date, fee_title=None, fee_act_id=None, **kwargs):
        if not isinstance(begin_date, date) and not isinstance(end_date, date):
            raise CMBYJFException(None, "begin_date 与 end_date的类型需要为 datetime.date 形式")
        if not isinstance(detail, list):
            raise CMBYJFException(None, "detail的类型需要为 list 形式")

        begin_date = begin_date.strftime("%Y%m%d")
        end_date = end_date.strftime("%Y%m%d")

        biz_content = {
            "depart": self.depart,
            "detail": self._format_deatil(detail),
            "begin_date": begin_date,
            "end_date": end_date
        }

        if not fee_act_id and not fee_title:
            raise CMBYJFException(None, 'fee_act_id 和 fee_title 不能同时为空')
        if fee_act_id:
            biz_content.update({
                "fee_act_id": fee_act_id
            })
        else:
            biz_content.update({
                "fee_title": fee_title
            })

        biz_content.update({
            "sum_cnt": len(detail),
        })

        sum_amt = 0.0
        for d in detail:
            sum_amt += float(d[7])
        biz_content.update({
            "sum_amt": sum_amt,
        })
        biz_content.update(kwargs)
        data = self.build_body(biz_content)
        return self._post_data('import', data)

    def api_cmbpay_query(self, fee_act_id, **kwargs):
        biz_content = {
            "fee_act_id": fee_act_id,
        }
        biz_content.update(kwargs)

        data = self.build_body(biz_content)
        return self._post_data('query', data)

    def api_cmbpay_delete(self, delete_list):
        delete = list()
        for d in delete_list:
            delete.append('{}~^'.format(d))
        biz_content = {
            'detail': delete
        }
        data = self.build_body(biz_content)

        return self._post_data('delete', data)

    def api_cmbpay_query_bank(self, fee_act_id, **kwargs):
        biz_content = {
            "fee_act_id": fee_act_id,
        }
        biz_content.update(kwargs)

        data = self.build_body(biz_content)
        return self._post_data('querybank', data)

    def api_cmbpay_trade_wap_pay(
        self, subject, out_trade_no, total_amount,
        return_url=None, notify_url=None, **kwargs
    ):
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "QUICK_WAP_PAY"
        }
        biz_content.update(kwargs)
        data = self.build_body(
            "cmbpay.trade.wap.pay",
            biz_content,
            return_url=return_url,
            notify_url=notify_url
        )
        return self.sign_data(data)

    def api_cmbpay_trade_app_pay(
        self, subject, out_trade_no, total_amount, notify_url=None, **kwargs
    ):
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "QUICK_MSECURITY_PAY"
        }
        biz_content.update(kwargs)
        data = self.build_body("cmbpay.trade.app.pay", biz_content, notify_url=notify_url)
        return self.sign_data(data)

    def api_cmbpay_trade_page_pay(self, subject, out_trade_no, total_amount,
                                  return_url=None, notify_url=None, **kwargs):
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "FAST_INSTANT_TRADE_PAY"
        }

        biz_content.update(kwargs)
        data = self.build_body(
            "cmbpay.trade.page.pay",
            biz_content,
            return_url=return_url,
            notify_url=notify_url
        )
        return self.sign_data(data)

    def api_cmbpay_trade_query(self, out_trade_no=None, trade_no=None):
        """
        response = {
          "cmbpay_trade_query_response": {
            "trade_no": "2017032121001004070200176844",
            "code": "10000",
            "invoice_amount": "20.00",
            "open_id": "20880072506750308812798160715407",
            "fund_bill_list": [
              {
                "amount": "20.00",
                "fund_channel": "cmbpayACCOUNT"
              }
            ],
            "buyer_logon_id": "csq***@sandbox.com",
            "send_pay_date": "2017-03-21 13:29:17",
            "receipt_amount": "20.00",
            "out_trade_no": "out_trade_no15",
            "buyer_pay_amount": "20.00",
            "buyer_user_id": "2088102169481075",
            "msg": "Success",
            "point_amount": "0.00",
            "trade_status": "TRADE_SUCCESS",
            "total_amount": "20.00"
          },
          "sign": ""
        }
        """
        assert (out_trade_no is not None) or (trade_no is not None),\
            "Both trade_no and out_trade_no are None"

        biz_content = {}
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        if trade_no:
            biz_content["trade_no"] = trade_no
        data = self.build_body("cmbpay.trade.query", biz_content)
        response_type = "cmbpay_trade_query_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_pay(
        self, out_trade_no, scene, auth_code, subject, notify_url=None, **kwargs
    ):
        """
        eg:
            self.api_cmbpay_trade_pay(
                out_trade_no,
                "bar_code/wave_code",
                auth_code,
                subject,
                total_amount=12,
                discountable_amount=10
            )
        failed response = {
            "cmbpay_trade_pay_response": {
                "code": "40004",
                "msg": "Business Failed",
                "sub_code": "ACQ.INVALID_PARAMETER",
                "sub_msg": "",
                "buyer_pay_amount": "0.00",
                "invoice_amount": "0.00",
                "point_amount": "0.00",
                "receipt_amount": "0.00"
            },
            "sign": ""
        }
        succeeded response =
            {
              "cmbpay_trade_pay_response": {
                "trade_no": "2017032121001004070200176846",
                "code": "10000",
                "invoice_amount": "20.00",
                "open_id": "20880072506750308812798160715407",
                "fund_bill_list": [
                  {
                    "amount": "20.00",
                    "fund_channel": "cmbpayACCOUNT"
                  }
                ],
                "buyer_logon_id": "csq***@sandbox.com",
                "receipt_amount": "20.00",
                "out_trade_no": "out_trade_no18",
                "buyer_pay_amount": "20.00",
                "buyer_user_id": "2088102169481075",
                "msg": "Success",
                "point_amount": "0.00",
                "gmt_payment": "2017-03-21 15:07:29",
                "total_amount": "20.00"
              },
              "sign": ""
            }
        """
        assert scene in ("bar_code", "wave_code"), 'scene not in ("bar_code", "wave_code")'

        biz_content = {
            "out_trade_no": out_trade_no,
            "scene": scene,
            "auth_code": auth_code,
            "subject": subject
        }
        biz_content.update(**kwargs)
        data = self.build_body("cmbpay.trade.pay", biz_content, notify_url=notify_url)
        response_type = "cmbpay_trade_pay_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_refund(self, refund_amount, out_trade_no=None, trade_no=None, **kwargs):
        biz_content = {
            "refund_amount": refund_amount
        }
        biz_content.update(**kwargs)
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        if trade_no:
            biz_content["trade_no"] = trade_no

        data = self.build_body("cmbpay.trade.refund", biz_content)
        response_type = "cmbpay_trade_refund_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_cancel(self, out_trade_no=None, trade_no=None):
        """
        response = {
        "cmbpay_trade_cancel_response": {
            "msg": "Success",
            "out_trade_no": "out_trade_no15",
            "code": "10000",
            "retry_flag": "N"
          }
        }
        """

        assert (out_trade_no is not None) or (trade_no is not None),\
            "Both trade_no and out_trade_no are None"

        biz_content = {}
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        if trade_no:
            biz_content["trade_no"] = trade_no

        data = self.build_body("cmbpay.trade.cancel", biz_content)
        response_type = "cmbpay_trade_cancel_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_close(self, out_trade_no=None, trade_no=None, operator_id=None):
        """
        response = {
            "cmbpay_trade_close_response": {
                "code": "10000",
                "msg": "Success",
                "trade_no": "2013112111001004500000675971",
                "out_trade_no": "YX_001"a
            }
        }
        """

        assert (out_trade_no is not None) or (trade_no is not None),\
            "Both trade_no and out_trade_no are None"

        biz_content = {}
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        if trade_no:
            biz_content["trade_no"] = trade_no
        if operator_id:
            biz_content["operator_id"] = operator_id

        data = self.build_body("cmbpay.trade.close", biz_content)
        response_type = "cmbpay_trade_close_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_precreate(self, subject, out_trade_no, total_amount, notify_url=None, **kwargs):
        """
        success response  = {
          "cmbpay_trade_precreate_response": {
            "msg": "Success",
            "out_trade_no": "out_trade_no17",
            "code": "10000",
            "qr_code": "https://qr.cmbpay.com/bax03431ljhokirwl38f00a7"
          },
          "sign": ""
        }
        failed response = {
          "cmbpay_trade_precreate_response": {
            "msg": "Business Failed",
            "sub_code": "ACQ.TOTAL_FEE_EXCEED",
            "code": "40004",
            "sub_msg": "订单金额超过限额"
          },
          "sign": ""
        }
        """
        biz_content = {
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "subject": subject
        }
        biz_content.update(**kwargs)
        data = self.build_body("cmbpay.trade.precreate", biz_content, notify_url=notify_url)
        response_type = "cmbpay_trade_precreate_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_fastpay_refund_query(
        self, out_request_no, trade_no=None, out_trade_no=None
    ):
        assert (out_trade_no is not None) or (trade_no is not None),\
            "Both trade_no and out_trade_no are None"

        biz_content = {"out_request_no": out_request_no}
        if trade_no:
            biz_content["trade_no"] = trade_no
        else:
            biz_content["out_trade_no"] = out_trade_no

        data = self.build_body("cmbpay.trade.fastpay.refund.query", biz_content)
        response_type = "cmbpay_trade_fastpay_refund_query_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_fund_trans_toaccount_transfer(
            self, out_biz_no, payee_type, payee_account, amount, **kwargs
    ):
        assert payee_type in ("cmbpay_USERID", "cmbpay_LOGONID"), "unknown payee type"
        biz_content = {
            "out_biz_no": out_biz_no,
            "payee_type": payee_type,
            "payee_account": payee_account,
            "amount": amount
        }
        biz_content.update(kwargs)
        data = self.build_body("cmbpay.fund.trans.toaccount.transfer", biz_content)
        response_type = "cmbpay_fund_trans_toaccount_transfer_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_fund_trans_order_query(self, out_biz_no=None, order_id=None):
        if out_biz_no is None and order_id is None:
            raise Exception("Both out_biz_no and order_id are None!")

        biz_content = {}
        if out_biz_no:
            biz_content["out_biz_no"] = out_biz_no
        if order_id:
            biz_content["order_id"] = order_id

        data = self.build_body("cmbpay.fund.trans.order.query", biz_content)
        response_type = "cmbpay_fund_trans_order_query_response"
        return self.verified_sync_response(data, response_type)

    def api_cmbpay_trade_order_settle(
        self,
        out_request_no,
        trade_no,
        royalty_parameters,
        **kwargs
    ):
        biz_content = {
            "out_request_no": out_request_no,
            "trade_no": trade_no,
            "royalty_parameters": royalty_parameters,
        }
        biz_content.update(kwargs)
        data = self.build_body("cmbpay.trade.order.settle", biz_content)
        response_type = "cmbpay_trade_order_settle_response"
        return self.verified_sync_response(data, response_type)

    def _verify_and_return_sync_response(self, raw_string, response_type):
        """
        return response if verification succeeded, raise exception if not
        As to issue #69, json.loads(raw_string)[response_type] should not be returned directly,
        use json.loads(plain_content) instead
        failed response is like this
        {
          "cmbpay_trade_query_response": {
            "sub_code": "isv.invalid-app-id",
            "code": "40002",
            "sub_msg": "无效的AppID参数",
            "msg": "Invalid Arguments"
          }
        }
        """
        response = json.loads(raw_string)
        # raise exceptions
        if "sign" not in response.keys():
            result = response[response_type]
            raise CMBYJFException(
                code=result.get("code", "0"),
                message=raw_string
            )

        sign = response["sign"]

        # locate string to be signed
        plain_content = self._get_string_to_be_signed(raw_string, response_type)

        if not self._verify(plain_content, sign):
            raise CMBYJFException
        return json.loads(plain_content)

    def verified_sync_response(self, data, response_type):
        url = self._gateway + "?" + self.sign_data(data)
        # raw_string = urlopen(url, timeout=15).read().decode()
        raw_string = ''
        return self._verify_and_return_sync_response(raw_string, response_type)

    def _get_string_to_be_signed(self, raw_string, response_type):
        """
        从同步返回的接口里面找到待签名的字符串
        """
        balance = 0
        start = end = raw_string.find("{", raw_string.find(response_type))
        # 从response_type之后的第一个｛的下一位开始匹配，
        # 如果是｛则balance加1; 如果是｝而且balance=0，就是待验签字符串的终点
        for i, c in enumerate(raw_string[start + 1:], start + 1):
            if c == "{":
                balance += 1
            elif c == "}":
                if balance == 0:
                    end = i + 1
                    break
                balance -= 1
        return raw_string[start:end]


class CmbYjfPay(CmbYjfBasePay):
    pass
