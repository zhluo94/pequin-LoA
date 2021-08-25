#!/bin/bash

echo 'Verifier setup'
./pepper_compile_and_setup_V.sh session_claiming_binary session_claiming_binary.vkey session_claiming_binary.pkey

echo 'Prover setup'
./pepper_compile_and_setup_P.sh session_claiming_binary

echo 'Verifier generating inputs'
bin/pepper_verifier_session_claiming_binary gen_input session_claiming_binary.inputs

echo 'Prover generating a proof'
start_time=$SECONDS
bin/pepper_prover_session_claiming_binary prove session_claiming_binary.pkey session_claiming_binary.inputs session_claiming_binary.outputs session_claiming_binary.proof
elapsed=$(( SECONDS - start_time ))
echo $elapsed

echo 'Verifier verifying the proof'
bin/pepper_verifier_session_claiming_binary verify session_claiming_binary.vkey session_claiming_binary.inputs session_claiming_binary.outputs session_claiming_binary.proof
