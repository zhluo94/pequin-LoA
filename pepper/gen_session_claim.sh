#!/bin/bash

echo 'Verifier setup'
./pepper_compile_and_setup_V.sh session_claiming session_claiming.vkey session_claiming.pkey

echo 'Prover setup'
./pepper_compile_and_setup_P.sh session_claiming

echo 'Verifier generating inputs'
bin/pepper_verifier_session_claiming gen_input session_claiming.inputs

echo 'Prover generating a proof'
start_time=$SECONDS
bin/pepper_prover_session_claiming prove session_claiming.pkey session_claiming.inputs session_claiming.outputs session_claiming.proof
elapsed=$(( SECONDS - start_time ))
echo $elapsed

echo 'Verifier verifying the proof'
bin/pepper_verifier_session_claiming verify session_claiming.vkey session_claiming.inputs session_claiming.outputs session_claiming.proof
