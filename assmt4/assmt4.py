import hashlib
import datetime
import requests
import pytz
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode

SUCC="400"
FAIL="404"

class Driver:
    def __init__(self, name, date_of_birth,transport_authority_server,mobile):
        self.name = name
        self.date_of_birth = date_of_birth
        self.mobile=mobile
        self.private_key, self.public_key = self.generate_keypair()
        self.transport_authority_server=transport_authority_server
        self.license=self.transport_authority_server.get_license(self)
        self.signature=self.sign_license()


    def generate_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    

    def sign_license(self):
        signature = self.private_key.sign(
           self.license.to_string().encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

class License:
    def __init__(self, name, license_number, date_of_exp):
        self.name = name
        self.license_number = license_number
        self.exp_date = date_of_exp

    def to_string(self):
        return f"{self.name}{self.license_number}{self.exp_date}"

class TransportAuthorityServer:
    def __init__(self):
        # Simulate database of driver licenses
        self.driver_database = {}
        self.i_database={}
        # Generate RSA key pair for digital signatures
        self.private_key, self.public_key = self.generate_rsa_keys()

    def get_license(self,driver):
        l = License(driver.name,"ABC12464127","2025-10-31")
        self.driver_database[l.license_number]={
            "name":driver.name,
            "DOB":driver.date_of_birth,
            "mobile":driver.mobile,
            "license":l,
            "public_key":driver.public_key,
            "active_cases":{},
            "History":{}
        }
        return l
    
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def start_verification(self,license_number,public_key):
        records=self.driver_database[license_number]
        otp="523453394"
        message=f'Dear {records["name"]}, U have been stopped for license Verification.License Number: {records["license"].license_number} Expiry Date: {records["license"].exp_date} OTP:{otp} . If its not u, Contact 911 right now.'
        idg="A001"
        self.i_database[idg]={"public_key":public_key,
                            "license":license_number,
                            "status":"START: verification code sent",
                            "OTP" : otp
                                        }
        ciphertext = records["public_key"].encrypt(
                        message.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
        send_text(records['mobile'],ciphertext)
        return idg

    def continue_verification(self,idg,signature):
        r=self.i_database[idg]
        try:
            r["public_key"].verify(
                signature,
                r["OTP"].encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return self.sign_data(SUCC)
        except Exception as e:
            print("Error: ",e)
            return self.sign_data(FAIL)
        
    
    def sign_data(self, data):        
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_license(self, license_number, signature):
        current_time = self.get_current_time()
        if current_time is None:
            print("Error: Unable to verify license. Failed to obtain current time.")
            return False

        license_info = None
        try:
            license_info=self.driver_database[license_number]
        except Exception:
            license_info = None

        if license_info:
            l=license_info["license"]
            expiry_date = datetime.datetime.strptime(license_info["license"].exp_date, "%Y-%m-%d")
            expiry_date = expiry_date.replace(tzinfo=pytz.utc)  # Make expiry_date offset-aware
            if current_time < expiry_date:
                
                try:
                    license_info['public_key'].verify(
                        signature,
                        f'{l.name}{l.license_number}{l.exp_date}'.encode(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return [True,license_info]
                except Exception as e:
                    print("Error: Signature verification failed.", e)
                    return [False,license_info]
            else:
                print("Error: License has expired.")
                return [False,license_info]
        else:
            print("Error: License not found in the database.")
            return [False,license_info]

    def get_current_time(self):
        try:
            # Send an HTTPS request to a well-known server to fetch the current time
            response = requests.get('https://worldtimeapi.org/api/ip')
            if response.status_code == 200:
                data = response.json()
                current_time = datetime.datetime.strptime(data['datetime'], '%Y-%m-%dT%H:%M:%S.%f%z')
                return current_time
            else:
                print("Error: Unable to fetch current time.")
                return None
        except Exception as e:
            print("Error:", e)
            return None

class PoliceOfficer:
    def __init__(self, transport_authority_server):
        self.transport_authority_server = transport_authority_server
        self.private_key, self.public_key = self.generate_rsa_keys()

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_data(self, data):
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def request_verification(self, license_number):
        # Access the server's database using the provided license number
        idg=self.transport_authority_server.start_verification(license_number, self.public_key)
        otp = input("Enter OTP:")
        status=self.transport_authority_server.continue_verification(idg,self.sign_data(otp))
        try:
            self.transport_authority_server.public_key.verify(
                status,
                SUCC.encode(),
                padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                            ),
                        hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Error: ",e)
            return False





    # Create transport authority server
transport_server = TransportAuthorityServer()
# Create police officer instance
police_officer = PoliceOfficer(transport_server)
driver=Driver("Bob","2003-10-05",transport_server,"9850283991")
print("Welcome to On-the-go verification of Driver’s License system.")

def send_text(mobile,ciphertext,pk=driver.private_key):
    mssg=pk.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    mssg=mssg.decode()
    print(f"TEXT TO {mobile}: \n")
    print(mssg)

# Simulate communication with a driver's device
driver_license_number = input("Enter license number: ")
# Verify license
verification_result = police_officer.request_verification(driver_license_number)
if verification_result:
    status,report=transport_server.verify_license(driver.license.license_number,driver.signature)
    if(status):
        print("License verified successfully.")
        print(report)
else:
    print("License verification failed.")


