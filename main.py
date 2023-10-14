from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

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

origin = "http://localhost:5000"
rp_id = "localhost"

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
def handler_verify_registration_response(request: Request):
    global current_registration_challenge
    global logged_in_user_id

    body = request.body()
    print(body)

    # try:
    #     credential = RegistrationCredential.parse_raw(body)
    #     verification = verify_registration_response(
    #         credential=credential,
    #         expected_challenge=current_registration_challenge,
    #         expected_rp_id=rp_id,
    #         expected_origin=origin,
    #     )
    # except Exception as err:
    #     raise HTTPException(status_code=400, detail=str(err))

    # user = in_memory_db[logged_in_user_id]
    # new_credential = Credential(
    #     id=verification.credential_id,
    #     public_key=verification.credential_public_key,
    #     sign_count=verification.sign_count,
    #     transports=json.loads(body).get("transports", []),
    # )

    # user.credentials.append(new_credential)
    # print(user)
    return JSONResponse(content={"verified": True})


uvicorn.run(app=app, host="0.0.0.0")
