import pytest

from aioairctrl.coap.encryption import DigestMismatchException, EncryptionContext


@pytest.fixture
def ctx():
    c = EncryptionContext()
    c.set_client_key("AABBCCDD")
    return c


class TestEncryptDecryptRoundtrip:
    def test_simple_payload(self, ctx):
        plaintext = '{"state":{"reported":{"pwr":"1"}}}'
        encrypted = ctx.encrypt(plaintext)
        result = ctx.decrypt(encrypted)
        assert result == plaintext

    def test_empty_string(self, ctx):
        encrypted = ctx.encrypt("")
        assert ctx.decrypt(encrypted) == ""

    def test_unicode_payload(self, ctx):
        plaintext = "hello world"
        encrypted = ctx.encrypt(plaintext)
        assert ctx.decrypt(encrypted) == plaintext

    def test_multiple_encryptions_are_distinct(self, ctx):
        plaintext = "test"
        enc1 = ctx.encrypt(plaintext)
        enc2 = ctx.encrypt(plaintext)
        assert enc1 != enc2

    def test_decrypt_uses_key_embedded_in_payload(self, ctx):
        plaintext = "test payload"
        encrypted = ctx.encrypt(plaintext)
        # A fresh context with a different key should still decrypt because
        # the key is embedded in the ciphertext envelope
        ctx2 = EncryptionContext()
        ctx2.set_client_key("00000000")
        assert ctx2.decrypt(encrypted) == plaintext


class TestClientKeyCounter:
    def test_counter_increments_on_encrypt(self, ctx):
        initial_key = ctx._client_key
        ctx.encrypt("x")
        assert ctx._client_key != initial_key

    def test_counter_increments_by_one(self, ctx):
        ctx._client_key = "00000001"
        ctx.encrypt("x")
        assert ctx._client_key == "00000002"

    def test_key_embedded_in_output_is_incremented_value(self, ctx):
        ctx._client_key = "00000001"
        encrypted = ctx.encrypt("x")
        assert encrypted[:8] == "00000002"

    def test_counter_wraps_at_overflow(self, ctx):
        ctx._client_key = "FFFFFFFE"
        ctx.encrypt("x")
        assert ctx._client_key == "FFFFFFFF"


class TestDigestValidation:
    def test_tampered_ciphertext_raises(self, ctx):
        encrypted = ctx.encrypt("test")
        # Flip a character in the ciphertext portion (after the 8-char key)
        tampered = encrypted[:10] + ("0" if encrypted[10] != "0" else "1") + encrypted[11:]
        with pytest.raises(DigestMismatchException):
            ctx.decrypt(tampered)

    def test_tampered_digest_raises(self, ctx):
        encrypted = ctx.encrypt("test")
        # Flip the last character of the digest
        tampered = encrypted[:-1] + ("0" if encrypted[-1] != "0" else "1")
        with pytest.raises(DigestMismatchException):
            ctx.decrypt(tampered)


class TestKnownVectors:
    """Decrypt known payloads captured from real devices.

    These tests validate the decrypt implementation against actual protocol
    data, independently of the encrypt() implementation.
    """

    # Captured from device AC0850/11 at 192.168.179.42
    DEVICE_1_ENCRYPTED = (
        "F45D47295C5523D0B35EE7CF83FE3F694F46455C668A0B9A374B731059A6D5ED2E5D87A"
        "4747EE5D0EB4C5C3DE76634497E5692769F3A5525245F0925EAF2FE65B36C749EBEE19D"
        "C1B34052AEF9D58933C111545AF273A06B1A7F822A69BBD696DDACC191FA468B96B2C18"
        "73C300D965A577F8814EEA4F3995EAD0976576375E450C79B8AC3060C81EB01EF6E77F4"
        "5C170D8EFB426B80505C24D5898A43AFCE8BBE5105E552F76FB284149DD34DB29F1F0CB"
        "16CD8875AB57686ECB2893523FEA30036C697F0B8A4F6E99F65902C2E68DD02CD757EE0"
        "8A70104A1640795593AED91803188845541F0DD5B991B90DFD24D1B49530FA7B383AA0D"
        "1A19F5850996D4EFAEFD12F7F0D7C5AF7DF9093D2475B24D67B5287F9007EF7164963EF"
        "053E2FCEECABF965221F3136ABA925D35264A4C9594EC6560ADC487A0DB8521609DD8F3"
        "28A52D9B160F545FCA07431526385DFEA870B7CD4B916BFA560465EAF6D0B217053D46F"
        "E888C6ECB81C9B2E0529365B1F76A062131695E7903F655A15AB141C7777893F75EB380"
        "72E54A43AF3EE061A36C5843A521FA265406E086338D38CB1E7561541E729EBC23C497A"
        "9ADE29BF0F8B6109398E06AA97DC2844BE5596A21FB1807CE334C955D9E94C3F19FA522"
        "7C852B44086BECCC9D19829902A18781C069F9646374C9873F417A49C697E000CEBBAB2"
        "E3E4F190EC1F106941EC6F59C50D96E92EB1A4D64AF4B8E663826E84D2A335CE8866D2C"
        "9BC28D02F1798633D30C839CD49A700B5B5DF8539654EE83BD96CF3058CF3A3842E8EE6"
        "9A80F3D8EBE44CCC4FAED9CCFC0A575026277DC84DDBF271994D8DE7F596ED7D6E24243"
        "14663C6D4776DEA03E2F9C8EBBC8CAD9C225D9A2BEBFAF9B1BE50CED69EFDEA0EC4D2D"
        "53C0DBA334C05107F21D86C7E3046736344CB554F657477767A09E0F952F8881E29E32C"
        "1D1249B3738EA05193CB36CB397F1855E90D8E5528EA20CB803EFD8FD6C966A14A2D0AB"
        "491AB9A182C63552373E009799A81B584E55B94E2CF62F0A2582222CE6BA21EB0460CA3"
        "6B3F17A1120123712B237F9465742A0F4E3FE553921D3827B515FA6493ADCAB549C020C"
        "9C6F6F05531F8C9C9C707470509EDB950CC5D585A31E51D73F28C08B2C75B71AEE638F8"
        "6A8E5C920A802D4DD60689CB088FCEC10E51F99F4821BC9B2910F62FD03728A0248CFCEB"
    )
    DEVICE_1_PLAINTEXT = (
        '{"state":{"reported":{"D01-02":"Purifier product","D01-03":"Arbeitszimmer",'
        '"D01-04":"Pluto","D01-05":"AC0850/11","D01-07":"English","D01-08":2,"D01-09":1,'
        '"D01-10":0,"D01-11":0,"D01-20":"0.1.2","D01-21":"1.1.1","MCUBoot":true,'
        '"Runtime":2894078635,"rssi":-47,"otacheck":false,"wifilog":false,'
        '"free_memory":54704,"WifiVersion":"AWS_Philips_AIR@91.1",'
        '"ProductId":"6cfff702cc3e11eca3f10217247a73aa",'
        '"DeviceId":"02bce902aafd11eeb852ffe3bb3393ec",'
        '"StatusType":"status","ConnectType":"Online","D03-02":"ON","D03-03":false,'
        '"D03-04":100,"D03-05":100,"D03-11":"A","D03-12":"Auto General","D03-13":"1",'
        '"D03-32":1,"D03-33":2,"D03-42":"PM2.5","D03-43":"PM2.5","D03-44":4,'
        '"aqit_ext":0,"D03-64":0,"D05-02":"A3","D05-03":"none","D05-07":720,'
        '"D05-08":4800,"D05-09":0,"D05-13":720,"D05-14":3300,"D05-15":0},"desired":null}}'
    )

    # Captured from device AC2729/10 at 192.168.179.229
    DEVICE_2_ENCRYPTED = (
        "86ABD25E53DA53C9634039EEF8A4C550BBD2C26ECBAEDC11E13FC94E7AC7B700986CF45"
        "6A8354BA8401F2E1895ED0FE2FCCC7BEEFF598116A4B59C0C790D75421E78CA15D69902"
        "BF427F58C62F984E2753D3B1F15394B2284B72AC46C9B892D488BC0D1EC83277A896C85"
        "514E561BBF87E9D4443BA7E9179C23D8EE857682508B1C30D2A6C7147CD06748EF4A4A7"
        "B2B7F769E72DAEAEB0C1943902474ED127CA3BEDACCABF5B7000123007DCAB4F23D09BA"
        "029132D377362FA3F78B70118AD818CD892EA921665B9FF19E749B3BF15E907EA3BCE1E"
        "B5B9130FD57D539F488661B08E19EC41532DE14F2A31C147BBEB068F1106955922BDC70"
        "089331C56DC981010B6899D3E5DA2B2B827D3BAFC65110DA512CAD6EC2B43B181872E14"
        "2B7B711C8BE4B8E8EA7A8557586958CDD29076111CF74AEC0B8F3CF971964B3222E7582"
        "86127BAED34CE9D7D8691FF119287088B18539C7F3D35BB5AD7965B53A72B6638EB4732"
        "4C1EFFC78827A3BF5DE5ECDB03DD338513A626E591CF1B07870EF6220CAD83452133304"
        "034E96416A7625AE91DA9CEAD3C4B3FA2CD3274D709427709E8185FC102B7E50264699A"
        "AC0032806D7E0F7861EC7F3CCA3F6F71CA019607A3A7D05722BB951401CE3985EE71846"
        "A98EB643428E81C2CE8B7EB0DA6E89E2FB311DC0CF3FF2961DA5C124B6E88B146A344A0"
        "560A200224863E2EC90D913C239B006B84AB77A5B7DD471E4F8D696400C1C598F990621"
        "2DE55C60E59F1493994CFD87DFF561798C53A9D5ED7A0B5FC690B90A9ED61F02928AD7C"
        "20C324FCDBB9210476F295558DC593CDB59354346BA13CF5877DDE05864E04A17E0CD64"
        "F73BB66B8D0444C0B8666ABF21F0FCDEF8A526DA68F72955F4D7AA9B2F33DF075D09178"
        "C1D9EA0FF390E4CB0E33DC86D4714AE3FED5548D7E8040A894A1956A8D73387242DA3A0"
        "589C24941C61186D7B95F3D3C8651962DA005306472F919CFB0C9182E3ED71985BBE406"
        "9D9B9C7FE37917202A32568EE6B4"
    )
    DEVICE_2_PLAINTEXT = (
        '{"state":{"reported":{"name":"Schlafzimmer","type":"AC2729","modelid":"AC2729/10",'
        '"swversion":"0.2.1","range":"MicroMario","Runtime":482315086,"rssi":-78,'
        '"otacheck":false,"wifilog":false,"free_memory":56024,'
        '"WifiVersion":"AWS_Philips_AIR@91.1",'
        '"ProductId":"85bc26fae62611e8a1e3061302926720",'
        '"DeviceId":"3c84c6c8123311ebb1ae8e3584d00715",'
        '"StatusType":"status","ConnectType":"Online","om":"0","pwr":"0","cl":false,'
        '"aqil":0,"uil":"0","dt":0,"dtrs":0,"mode":"P","func":"P","rhset":60,"rh":52,'
        '"temp":22,"pm25":10,"iaql":3,"aqit":4,"aqit_ext":0,"ddp":"1","rddp":"1",'
        '"err":49411,"wl":0,"fltt1":"A3","fltt2":"C7","fltsts0":0,"fltsts1":2716,'
        '"fltsts2":2716,"wicksts":2716},"desired":null}}'
    )

    def test_decrypt_device_1(self):
        ctx = EncryptionContext()
        result = ctx.decrypt(self.DEVICE_1_ENCRYPTED)
        assert result == self.DEVICE_1_PLAINTEXT

    def test_decrypt_device_2(self):
        ctx = EncryptionContext()
        result = ctx.decrypt(self.DEVICE_2_ENCRYPTED)
        assert result == self.DEVICE_2_PLAINTEXT

    def test_decrypt_device_1_is_valid_json(self):
        import json
        ctx = EncryptionContext()
        result = ctx.decrypt(self.DEVICE_1_ENCRYPTED)
        parsed = json.loads(result)
        assert parsed["state"]["reported"]["D01-05"] == "AC0850/11"

    def test_decrypt_device_2_is_valid_json(self):
        import json
        ctx = EncryptionContext()
        result = ctx.decrypt(self.DEVICE_2_ENCRYPTED)
        parsed = json.loads(result)
        assert parsed["state"]["reported"]["type"] == "AC2729"


class TestKeyNotSet:
    def test_encrypt_without_key_raises(self):
        ctx = EncryptionContext()
        with pytest.raises(ValueError):
            ctx.encrypt("test")

    def test_increment_without_key_raises(self):
        ctx = EncryptionContext()
        with pytest.raises(ValueError):
            ctx._increment_client_key()
