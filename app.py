import streamlit as st
import os
import random
from dotenv import load_dotenv
from google import genai

# ================= IMPORTS =================
from utils.gemini_analysis import (
    get_severity_color,
    get_score_color,
    get_category_icon,
    create_annotated_text_html
)

from utils.file_processor import process_uploaded_file
from utils.scoring import analyze_message

from data.quiz_examples import QUIZ_EXAMPLES, COMPARISON_EXAMPLES
from data.url_examples import (
    URL_QUIZ_EXAMPLES,
    URL_SAFETY_TIPS,
    PHISHING_CASE_STUDIES
)

# ================= CONFIG =================
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

st.set_page_config(
    page_title="Digital Literacy Assistant",
    page_icon="🛡️",
    layout="wide"
)

# ================= SESSION STATE =================
defaults = {
    "quiz_mode": False,
    "current_quiz": None,
    "quiz_revealed": False,
    "quiz_score": 0,
    "quizzes_taken": 0
}

for k, v in defaults.items():
    st.session_state.setdefault(k, v)

# ================= TITLE =================
st.title(" Digital Literacy Assistant")
st.markdown(
    "Analyze suspicious messages, emails, posts, and URLs. "
    "Learn how scams work and how to stay safe online."
)

# ================= SIDEBAR =================
with st.sidebar:
    page = st.radio("Choose a section:", ["🔍 Analyze Text", "📖 Learn More"])

    if st.session_state.quizzes_taken > 0:
        accuracy = st.session_state.quiz_score / st.session_state.quizzes_taken
        st.markdown("###  Quiz Progress")
        st.metric("Quizzes Taken", st.session_state.quizzes_taken)
        st.metric("Average Score", f"{accuracy:.0f}%")

# =====================================================
# ================= ANALYZE TEXT ======================
# =====================================================
if page == "🔍 Analyze Text":
    st.header(" Analyze Your Text")

    tab1, tab2 = st.tabs([" Type / Paste", "📎 Upload File"])
    user_text = None

    with tab1:
        user_text = st.text_area("Paste text here", height=200)

    with tab2:
        uploaded = st.file_uploader(
            "Upload file",
            type=["pdf", "docx", "txt", "png", "jpg", "jpeg"]
        )
        if uploaded:
            user_text = process_uploaded_file(uploaded)

    if st.button(" Analyze", type="primary") and user_text:
        result = analyze_message(user_text)

        if not result["success"]:
            st.error(result["error"])
            st.stop()

        data = result["data"]

        # ===== OVERALL SCORE =====
        score = data.get("overall_confidence_score", 0)
        st.markdown(f"## {get_score_color(score)} Overall Risk: {score}/100")
        st.progress(score / 100)
        st.info(data.get("recommendation", "Stay cautious."))

        # ===== AI RESULT =====
        st.markdown("###  AI Based Risk Classification")
        ml = data.get("ml_prediction", "unknown")
        conf = data.get("ml_confidence", 0)

        if ml == "scam":
            st.error(f" High Risk Scam ({conf}%)")
        elif ml == "suspicious":
            st.warning(f" Suspicious Content ({conf}%)")
        else:
            st.success(f" Appears Safe ({conf}%)")

        # ===== CATEGORY BREAKDOWN =====
        st.markdown("### Category Risk Breakdown")
        for cat, val in data.get("category_scores", {}).items():
            st.markdown(f"**{get_category_icon(cat)} {cat.replace('_',' ').title()}**")
            st.progress(val / 100, text=f"{val}/100")

        # ===== URL SAFETY =====
        if data.get("urls_found", 0) > 0:
            st.markdown("---")
            st.subheader("🔗 URL Safe Browsing Analysis")

            st.markdown("""
            **What is Safe Browsing?**  
            It checks whether links are known for **phishing, malware, or scams**
            using Google Safe Browsing + technical URL analysis.
            """)

            sb = data.get("safe_browsing_check", {})

            if sb.get("safe") is True:
                st.success(" Google Safe Browsing: URL not flagged")
            elif sb.get("safe") is False:
                st.error(" Google Safe Browsing: Dangerous URL detected")
            else:
                st.info(" Google Safe Browsing result unavailable")

            for i, u in enumerate(data.get("url_analyses", []), 1):
                risk = u.get("risk_score", 0)
                emoji = "🟢" if risk < 40 else "🟡" if risk < 60 else "🔴"

                with st.expander(f"{emoji} URL {i}: {u.get('url','Unknown')}"):
                    st.metric("Risk Score", f"{risk}/100")
                    st.write("**Domain:**", u.get("domain", "Unknown"))
                    st.write("**Protocol:**", u.get("scheme", "Unknown"))

                    flags = u.get("red_flags", [])
                    if flags:
                        for flag in flags:
                            st.write(
                                f"{get_severity_color(flag.get('severity','low'))} "
                                f"**{flag.get('flag','Warning')}** – "
                                f"{flag.get('explanation','Suspicious pattern detected')}"
                            )
                    else:
                        st.success("No technical red flags detected")

        # ===== DETAILED TABS =====
        st.markdown("---")
        t1, t2, t3 = st.tabs(["📝 Annotated Text", "🚩 Red Flags", " Summary"])

        with t1:
            html = create_annotated_text_html(
                user_text, data.get("suspicious_phrases", [])
            )
            st.markdown(html, unsafe_allow_html=True)

        with t2:
            flags = data.get("red_flags", [])
            if flags:
                for f in flags:
                    st.warning(f"{f.get('flag')} – {f.get('explanation')}")
            else:
                st.success("No major warning signs detected.")

        with t3:
            st.markdown(
    f"**Overall Assessment:**\n\n"
    f"{data.get('overall_assessment', 'No summary available.')}"
)

            if data.get("suspicious_phrases"):
              st.markdown("###  Suspicious Phrases")
              for s in data["suspicious_phrases"]:
               phrase = s.get("phrase", "Unknown phrase")
               reason = s.get("reason", "")
               st.info(f"**Phrase:** {phrase}\n**Reason:** {reason}")


# =====================================================
# ================= LEARN MORE =========================
# =====================================================
elif page == "📖 Learn More":
    st.header(" Learn About Online Safety")

    l1, l2, l3, l4 = st.tabs([
        "🚩 Red Flags",
        "🎯 Quiz",
        "🔄 Compare",
        "🔗 URL Safety"
    ])

    with l1:
        st.markdown("""
        ###  Common Scam Red Flags
        - Urgency & threats  
        - Asking for OTP / bank details  
        - Fake rewards or job offers  
        - Suspicious links  
        """)

    with l2:
        if not st.session_state.quiz_mode:
            if st.button("▶ Start Quiz"):
                st.session_state.quiz_mode = True
                st.session_state.current_quiz = random.choice(QUIZ_EXAMPLES)
                st.session_state.quiz_revealed = False
                st.rerun()
        else:
            quiz = st.session_state.current_quiz
            st.markdown(f"**Message:**\n\n{quiz['text']}")

            if st.button("Reveal Answer"):
                st.session_state.quiz_revealed = True
                st.session_state.quizzes_taken += 1
                st.session_state.quiz_score += quiz.get("risk_score", 0)
                st.rerun()

            if st.session_state.quiz_revealed:
                st.info(
                    quiz.get("explanation") or
                    quiz.get("reason") or
                    "This message contains common scam indicators."
                )

                if st.button("➡ Next Question"):
                    st.session_state.current_quiz = random.choice(QUIZ_EXAMPLES)
                    st.session_state.quiz_revealed = False
                    st.rerun()

    with l3:
        example = random.choice(COMPARISON_EXAMPLES)
        c1, c2 = st.columns(2)
        with c1:
            st.error(example["suspicious"])
        with c2:
            st.success(example["legitimate"])

    with l4:
        st.subheader("🔗 URL Safety Education")
        for tip in URL_SAFETY_TIPS["basic_checks"]:
            st.markdown(f"- {tip}")

        quiz = random.choice(URL_QUIZ_EXAMPLES)
        st.success(f"Legitimate: {quiz['legitimate']}")
        st.error(f"Phishing: {quiz['phishing']}")

        with st.expander("Why is this dangerous?"):
            st.write(
                quiz.get(
                    "explanation",
                    "This URL uses deceptive patterns common in phishing attacks."
                )
            )

        for case in PHISHING_CASE_STUDIES:
            with st.expander(case["title"]):
                st.warning(case["phishing_url"])
                st.write(case["lesson"])

# ================= FOOTER =================
st.markdown("---")
st.markdown(" Digital Literacy Assistant | Hack-o-Verse 2026")
