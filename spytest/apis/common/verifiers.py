from spytest import st

def na_verifier():
    st.log("na_verifier")
    return True

def l2_verifier():
    st.log("l2_verifier")
    return False

def get_verifiers():
    verifiers = dict()
    verifiers["NA"] = na_verifier
    verifiers["L2"] = l2_verifier
    return verifiers

