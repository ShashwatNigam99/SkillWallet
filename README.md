# Digital-id
Digital ID implementation using Hyperledger-Sawtooth blockchain platform

## Command to compile .protos files
##### General command: protoc --proto_path=src --python_out=dest src/file.proto
1. cd skill-wallet
1. protoc --proto_path=. --python_out=. protobuf/file.proto

## Commands to run Sawtooth Processes
1. sudo -u sawtooth sawtooth-validator -vv
1. sudo -u sawtooth devmode-engine-rust -v --connect tcp://localhost:5050
1. sudo -u sawtooth sawtooth-rest-api -v
1. sudo -u sawtooth settings-tp -v

## Commands to run Digital-ID application Processes
Change directory to the project folder using "cd <project-folder-name>" command
1. sudo ./tfprocessor/digitalid_tp.py --url [-l] rest-api-url --connect [-C] validator-url [-v/-vv/-vvv]
1. sudo ./tfprocessor/digitalid_certifier_tp.py --url [-l] rest-api-url --connect [-C] validator-url
1. sudo ./tfprocessor/peer_verification_tp.py --url [-l] rest-api-url --connect [-C] validator-url
1. sudo ./tfprocessor/shareid_tp.py --url [-l] rest-api-url --connect [-C] validator-url
1. sudo ./certifier/certifier_events_cli.py --url [-l] rest-api-url --connect [-C] validator-url -u [--user] certifier-name
1. sudo ./user/user_events_cli.py --url [-l] rest-api-url --connect [-C] validator-url -u [--user] user-name
1. sudo ./user/userwallet.py [id_wallet, request, peer_verify, attest_peer, confirm, display, update, disable, ack_disable_req, request_recovery, credibility_inc] --user [-u] user 
    --url [-l] rest-api-url
1. sudo ./certifier/certifier_wallet.py [certifier_wallet, send_ack, attest_peer, process_request --address [-a] address , 
                                        process_pending_requests, ack_disable_req] 
                                        --user [-u] user
                                        --url [-l] rest-api-url 
                                        [-v/-vv/-vvv]
                                    


