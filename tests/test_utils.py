from core.utils import identify_ioc_type, defang_ioc


def test_identify_ioc_type():
    assert identify_ioc_type("1.1.1.1")[0] == "ip"
    assert identify_ioc_type("2606:4700:4700::1111")[0] == "ip"
    assert identify_ioc_type("44d88612fea8a8f36de82e1278abb02f")[0] == "hash"
    assert identify_ioc_type("https://evil.example.com")[0] == "url"


def test_defang_ioc():
    assert defang_ioc("http://malware.com") == "hxxp[://]malware[.]com"
    assert defang_ioc("https://c2.server.com/drop") == "hxxps[://]c2[.]server[.]com/drop"
    assert defang_ioc("192.168.1.1") == "192[.]168[.]1[.]1"