from cgraph import ids


def test_nist():
    assert ids.nist_80053("ac-2.1") == "AC-2(1)"
    assert ids.nist_80053("AC-02(01)") == "AC-2(1)"
    assert ids.nist_80053("AC-02") == "AC-2"
    assert ids.nist_80053("si-10 (6)") == "SI-10(6)"
    assert ids.nist_80053("nonsense") is None
    assert ids.nist_req("IA-05(07)") == "NIST-800-53-r5:IA-5(7)"


def test_cwe_capec_attack_cve():
    assert ids.cwe("CWE-89: Improper Neutralization") == "CWE-89"
    assert ids.cwe("079") == "CWE-79"
    assert ids.capec("66") == "CAPEC-66"
    assert ids.attack_technique("1574.010") == "T1574.010"
    assert ids.attack_technique("T1190") == "T1190"
    assert ids.attack_technique("AML.T0051") is None
    assert ids.cve("GHSA-x / cve-2021-44228") == "CVE-2021-44228"
