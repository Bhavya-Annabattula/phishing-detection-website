from flask import Flask, render_template, request
import pickle
import pipeline_utils  # Required for unpickling URLTextPreprocessor

app = Flask(__name__)

# Load unified pipeline artifact containing preprocessor, vectorizer, and classifier
PIPELINE_PATH = "phishing_pipeline.pkl"
print(f"Loading model artifact from {PIPELINE_PATH}...")
with open(PIPELINE_PATH, "rb") as f:
    pipeline = pickle.load(f)
print(f"Model loaded successfully. Classes: {pipeline.classes_}")

# Dynamically map class indices
CLASSES = list(pipeline.classes_)
BAD_INDEX = CLASSES.index("bad")
GOOD_INDEX = CLASSES.index("good")


@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        raw_url = request.form.get('URL', '').strip()

        if not raw_url:
            return render_template(
                "index.html",
                predict="Please enter a valid URL."
            )

        # Single pipeline inference (raw URL -> preprocessor -> vectorizer -> classifier)
        prediction = pipeline.predict([raw_url])[0]
        probabilities = pipeline.predict_proba([raw_url])[0]

        bad_confidence = probabilities[BAD_INDEX] * 100
        good_confidence = probabilities[GOOD_INDEX] * 100

        if prediction == 'bad':
            predict = f"This is a Phishing Website!! (Confidence: {bad_confidence:.1f}%)"
        elif prediction == 'good':
            predict = f"This is a Secure Website!! (Confidence: {good_confidence:.1f}%)"
        else:
            predict = "Something Went Wrong"

        return render_template("index.html", predict=predict)

    else:
        return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=False)
