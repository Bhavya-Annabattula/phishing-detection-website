from flask import Flask, render_template, request
import pickle
import re

app = Flask(__name__)

vector = pickle.load(open("vectorizer.pkl",'rb'))
model = pickle.load(open("phishing.pkl",'rb'))



@app.route("/", methods=['GET','POST' ])
def index():
    if request.method == "POST":
        URL = request.form['URL']
        #print(URL)  

        cleaned_URL = re.sub(r'^https?://(www\.)?','',URL)
        #print(cleaned_URL)
        predict = model.predict(vector.transform([cleaned_URL]))[0]
        #print(predict)
        if predict == 'bad':
            predict = "This is a Phishing Website!!"
        elif predict =='good':
            predict = "This is a Secure Website!!"
        else :
            predict = "Something Went Wrong"

        return render_template("index.html",predict=predict )


    else:
       return render_template("index.html")



if __name__=="__main__":
     app.run(debug=False)