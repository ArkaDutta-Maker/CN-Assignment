#!/bin/bash

# Configuration parameters
BITSTREAM_FILE="msg.bits"
PAYLOAD_SIZE=256
CRC_BITS=32
WINDOW_SIZE=16
OUTPUT_CSV="arq_test_results.csv"
TIMEOUT_MS=1000

# Write CSV header
# echo "TestCase,ARQ_Scheme,DropProb,ErrorProb,DelayProb,TotalFrames,TotalTransmissions,TotalTimeMs,Efficiency,AvgRTT,Throughput(Mbps)" > "$OUTPUT_CSV"

test_case=55

for scheme in sr; do
    for drop_prob in $(seq 0.0 0.3 0.6); do
        for err_prob in $(seq 0.0 0.1 0.2); do
            for delay_prob in $(seq 0.0 0.1 0.2); do
                echo "[*] Running Test Case #$test_case: Drop_prob=$drop_prob Scheme=$scheme, ErrorProb=$err_prob, DelayProb=$delay_prob"

            # Start receiver in background with proper inputs
                if [[ "$scheme" == "gbn" || "$scheme" == "sr" ]]; then
                    ./receiver <<EOF >/dev/null 2>&1 &
$CRC_BITS
$scheme
$WINDOW_SIZE
$drop_prob
EOF
                else
                    ./receiver <<EOF >/dev/null 2>&1 &
$CRC_BITS
$scheme
$drop_prob
EOF
                fi
                # Wait for receiver to start listening on port
                sleep 1
                receiver_pid=$!
                if [[ "$scheme" == "gbn" || "$scheme" == "sr" ]]; then
                    TIMEOUT_MS=5000
                    output=$(printf "%s\n%s\n%s\n%s\n%s\n%s\n" \
                        "$BITSTREAM_FILE" "$PAYLOAD_SIZE" "$CRC_BITS" "$TIMEOUT_MS" "$scheme" "$WINDOW_SIZE" "$err_prob" "$delay_prob" | ./stats)
                else
                    output=$(printf "%s\n%s\n%s\n%s\n%s\n" \
                        "$BITSTREAM_FILE" "$PAYLOAD_SIZE" "$CRC_BITS" "$TIMEOUT_MS" "$scheme" "$err_prob" "$delay_prob" | ./stats)
                fi


                # Extract statistics from sender output
                total_frames=$(echo "$output" | grep "Total Frames:" | awk '{print $3}')
                total_trans=$(echo "$output" | grep "Total Transmissions:" | awk '{print $3}')
                total_time=$(echo "$output" | grep "Total Time:" | awk '{print $3}')
                efficiency=$(echo "$output" | grep "Efficiency (useful frames / total transmissions):" | awk '{print $7}')
                avg_rtt=$(echo "$output" | grep "Average Propagation Delay (RTT):" | awk '{print $5}')
                eff_throughput=$(echo "$output" | grep "Effective Throughput:" | awk '{print $3}')

                echo -e "\n$eff_throughput\n"
                # Append to CSV
                echo "$test_case,$scheme,$drop_prob,$err_prob,$delay_prob,$total_frames,$total_trans,$total_time,$efficiency,$avg_rtt,$eff_throughput" >> "$OUTPUT_CSV"

                #Clean up receiver process
                kill "$receiver_pid"
                wait "$receiver_pid" 2>/dev/null

                ((test_case++))
            done
        done
    done
done

echo "[+] All tests completed. Results saved to $OUTPUT_CSV"
