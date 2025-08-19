# JsonWebToken_Decoder
This is a python script designed to decode and read Json Web Token cookies and read them an the information stored within the cookie.

e.g 
python jwt_cookie_decoder.py eyJ1c2VyX2lkIjo2LCJ1c2VybmFtZSI6InN0M2FtcHVuayJ9.aKPWag.06VqSmXImcS28tW8tvmuDWWgxoI 

=== Decoded JWT ===
Header (json): {'user_id': 6, 'username': 'st3ampunk'}
Payload (raw-bytes): 68a3d66a
Signature (raw base64url): 06VqSmXImcS28tW8tvmuDWWgxoI
