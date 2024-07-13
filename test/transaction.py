from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', 'YOUR_SECRET_KEY')

@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    reference = request.json.get('reference')
    if reference:
        headers = {
            'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}'
        }
        url = f'https://api.paystack.co/transaction/verify/{reference}'
        response = requests.get(url, headers=headers)
        data = response.json()

        if response.status_code == 200 and data['status'] and data['data']['status'] == 'uccess':
            return jsonify({'status': 'uccess', 'data': data['data']}), 200
        else:
            return jsonify({'status': 'failure', 'data': data['data']}), 400
    return jsonify({'status': 'error', 'essage': 'Reference not provided'}), 400


if __name__ == '__main__':
    app.run(debug=True)

#use this code in the terminal for set up
#python -m venv venv
#source venv/bin/activate  # On Windows, use venv\Scripts\activate
#pip install Flask requests

#last line to run the whole thing
