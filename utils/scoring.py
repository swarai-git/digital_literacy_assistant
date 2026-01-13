from ml.predict import predict_message
from utils.gemini_analysis import analyze_text

def analyze_message(user_text):
    from ml.predict import predict_message
from utils.gemini_analysis import analyze_text_with_urls  # Changed import

def analyze_message(user_text):
    try:
        # ML prediction
        ml_label, ml_confidence = predict_message(user_text)

        # Gemini + URL analysis
        gemini_result = analyze_text_with_urls(user_text)  # Changed function

        if not gemini_result["success"]:
            return gemini_result

        data = gemini_result["data"]

        # Inject ML results
        data["ml_prediction"] = ml_label
        data["ml_confidence"] = ml_confidence

        # Adjust overall score using ML
        if ml_label == "scam":
            data["overall_confidence_score"] = max(
                data.get("overall_confidence_score", 0),
                ml_confidence
            )

        return {
            "success": True,
            "data": data
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }