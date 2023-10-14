from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
from models import Credential, UserAccount
from typing import Dict
import random
import json
from starlette.responses import JSONResponse

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import os
load_dotenv(".env")

origin = os.getenv("ORIGIN")
rp_id = os.getenv("RP_ID")

# A simple way to persist credentials by user ID
in_memory_db: Dict[str, UserAccount] = {}

# Register our sample user


# A simple way to persist challenges until response verification
current_registration_challenge = None
current_authentication_challenge = None

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(path="/")
def home():
    return "Home"


@app.get(path="/generate-registration-options")
def handler_generate_registration_options(username: str):
    # if mosh sends me the username and lets say the user_id is some number
    global current_registration_challenge, logged_in_user_id
    logged_in_user_id = random.randint(1, 1000000)

    print(f"User ID: {logged_in_user_id}")
    print(f"Username: {username}")

    in_memory_db[logged_in_user_id] = UserAccount(
        id=logged_in_user_id,
        username=username,
        credentials=[],
    )
    user = in_memory_db[logged_in_user_id]
    print(user)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="roll call",
        user_id=str(user.id),
        user_name=user.username,
        # user_display_name="Display Name",
        # attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            # authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        challenge=os.urandom(12),
        exclude_credentials=[
            {"id": cred.id, "transports": cred.transports, "type": "public-key"}
            for cred in user.credentials
        ],
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        # timeout=12000
    )
    current_registration_challenge = options.challenge
    print(current_registration_challenge)

    return options_to_json(options)


@app.post(path="/verify-registration-response")
async def handler_veaify_registration_response(request: Request):
    global current_registration_challenge
    global logged_in_user_id

    body = await request.json()  # returns a json object
    credential = json.dumps(body, indent=4)  # returns  json string
    credential = json.loads(credential)

    print(credential)

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_registration_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as err:
        raise HTTPException(status_code=400, detail=str(err))

    user = in_memory_db[logged_in_user_id]
    # I am meant to store the credential and the user attached to this credential
    new_credential = Credential(
        id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=credential["response"]["transports"],
    )

    user.credentials.append(new_credential)
    print(user)
    return JSONResponse(content={"verified": True})


@app.get(path="/generate-authentication-options")
def handler_generate_authentication_options():
    global current_authentication_challenge
    global logged_in_user_id

    user = in_memory_db[logged_in_user_id]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"type": "public-key", "id": cred.id, "transports": cred.transports}
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    current_authentication_challenge = options.challenge

    return options_to_json(options)


@app.post("/verify-authentication-response")
async def hander_verify_authentication_response(request: Request):
    global current_authentication_challenge
    global logged_in_user_id

    body = await request.json()  # returns a json object

    try:
        credential = json.dumps(body, indent=4)  # returns  json string
        credential = json.loads(credential)

        # Find the user's corresponding public key
        user = in_memory_db[logged_in_user_id]
        user_credential = None
        for _cred in user.credentials:
            if _cred.id == credential.raw_id:
                user_credential = _cred

        if user_credential is None:
            raise Exception("Could not find corresponding public key in DB")

        # Verify the assertion
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_authentication_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    # Update our credential's sign count to what the authenticator says it is now
    user_credential.sign_count = verification.new_sign_count

    return {"verified": True}

uvicorn.run(app=app, host="0.0.0.0")
