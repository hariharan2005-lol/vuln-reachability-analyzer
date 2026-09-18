import streamlit as st
from dummy_vuln_lib import unsafe_deserialize


def process(data):
    return unsafe_deserialize(data)


st.title("Streamlit Dashboard")
val = st.text_input("Enter value")
process(val)
