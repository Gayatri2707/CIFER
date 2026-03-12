import requests
import json
import os

import random

BASE_URL = "http://localhost:5000"

def run_test():
    session = requests.Session()
    print("Testing CIFER API Flow...")

    # 1. Register a new user
    rand_id = random.randint(1000, 9999)
    auth_data = {"name": f"Test User {rand_id}", "email": f"test{rand_id}@test.com", "password": "password123"}
    r = session.post(f"{BASE_URL}/api/register", json=auth_data)
    print(f"Register: {r.status_code} - {r.text}")

    # 2. Login
    r = session.post(f"{BASE_URL}/api/login", json={"email": auth_data["email"], "password": auth_data["password"]})
    print(f"Login: {r.status_code} - {r.text}")

    if r.status_code != 200:
        print("Login failed, aborting test.")
        return

    # 3. Encrypt a file
    test_filepath = "test_file.txt"
    with open(test_filepath, "w") as f:
        f.write("This is a highly top secret message.")
    
    with open(test_filepath, "rb") as f:
        files = {"file": f}
        data = {"receivers": json.dumps(["receiver@test.com"]), "expiry_hours": "1"}
        print("Uploading file for encryption...")
        r = session.post(f"{BASE_URL}/api/encrypt", files=files, data=data)
        
    print(f"Encrypt response status: {r.status_code}")
    if r.status_code != 200:
        print(f"Encrypt Error: {r.text}")
    
    if r.status_code == 200:
        # Save the encrypted image
        enc_image_path = "encrypted_output.jpg"
        with open(enc_image_path, "wb") as f:
            f.write(r.content)
        print(f"Successfully downloaded steganographic image to {enc_image_path}")

        # 4. Decrypt Upload (Extract Token)
        with open(enc_image_path, "rb") as f:
            files = {"file": f}
            r_dec_up = session.post(f"{BASE_URL}/api/decrypt-upload", files=files)
            print(f"Decrypt Upload: {r_dec_up.status_code} - {r_dec_up.text}")
            
            if r_dec_up.status_code == 200:
                dec_info = r_dec_up.json()
                token = dec_info.get("token")
                print(f"Successfully extracted token: {token}")

                # 5. OTP Request
                r_otp = session.post(f"{BASE_URL}/api/request-otp", json={"token": token, "email": "receiver@test.com"})
                print(f"OTP Request: {r_otp.status_code} - {r_otp.text}")
                
                # NOTE: Since we can't easily intercept the email in this automated test unless we mock it, 
                # we will just print success up to this point. Real OTP verification requires the code.
                if r_otp.status_code == 200:
                    print("OTP Request submitted successfully. Flow up to OTP is working.")
        
    # Cleanup
    if os.path.exists(test_filepath):
        os.remove(test_filepath)
    if os.path.exists("encrypted_output.jpg"):
        os.remove("encrypted_output.jpg")
        
if __name__ == "__main__":
    run_test()
