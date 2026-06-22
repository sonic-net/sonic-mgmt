#!/bin/bash
# Drive the Failure-scenario matrix: perturb -> run one test -> confirm it FAILS
# with the expected message -> revert (always). Negative test "passes" when the
# target test FAILS for the expected reason.
#
# MUST be invoked with cwd = repo's tests/ directory:
#   cd tests && bash transceiver/eeprom/negative_testing/run_matrix.sh
#
# Results are written to transceiver/eeprom/negative_testing/results/ (NOT under
# logs/, because run_tests.sh does `rm -rf logs` at startup and would delete them).
set -u

PB="python transceiver/eeprom/negative_testing/perturb_inventory.py"
RUNBASE='./run_tests.sh -n dvt_arista_test -i ../ansible/lab,../ansible/veos -u -d arista_sw2'
INV=../ansible/files/transceiver/inventory
CAT=$INV/attributes/eeprom/eeprom.json
PN=$INV/attributes/eeprom/transceivers/vendors/PINEWAVE/part_numbers/T-OH8CNT-NMT/eeprom.json
DUT=$INV/dut_info/arista_sw2.json
E0KEY="Ethernet0,Ethernet16,Ethernet64,Ethernet80,Ethernet128,Ethernet144,Ethernet352,Ethernet368,Ethernet416,Ethernet432,Ethernet480,Ethernet496"

RESDIR=transceiver/eeprom/negative_testing/results
rm -rf "$RESDIR"; mkdir -p "$RESDIR"
SUMMARY="$RESDIR/SUMMARY.txt"
: > "$SUMMARY"

# row: id | op | file | key | value | testpath | kfunc | expect_substr
ROWS=(
"1|set|$DUT|Ethernet0:7.vendor_sn|\"BADSN000000\"|transceiver/eeprom/test_eeprom_content.py|test_eeprom_content_verification_via_sfputil|expected 'BADSN000000'"
"2|set|$DUT|$E0KEY.vendor_rev|\"BADREV\"|transceiver/eeprom/test_eeprom_content.py|test_eeprom_content_verification_via_sfputil|expected 'BADREV'"
"3|set|$PN|cmis_revision|\"9.9\"|transceiver/eeprom/test_eeprom_content.py|test_eeprom_content_verification_via_show_cli|expected '9.9'"
"4|set|$CAT|transceivers.deployment_configurations.8x100G_DR8.sff8024_identifier|17|transceiver/eeprom/test_hexdump.py|test_identifier_byte_verification_via_sfputil|identifier byte mismatch"
"5|set|$CAT|defaults.vdm_supported|false|transceiver/eeprom/test_vdm_consistency.py|test_vdm_supported_consistency|vdm_supported mismatch"
"6|set|$CAT|defaults.cdb_background_mode_supported|false|transceiver/eeprom/cmis/test_cdb_background_mode.py|test_cdb_background_mode_support_test|CDB background mode mismatch"
"7|set|$CAT|defaults.breakout_stem_serial_number_pattern|\".*-ZZZ\$\"|transceiver/eeprom/test_breakout_serial.py|test_serial_number_pattern_validation_for_breakout_ports|serial number pattern mismatch"
"8|del|$CAT|defaults.cdb_stress_iteration_count||transceiver/eeprom/cmis/test_cdb_background_mode.py|test_cdb_background_mode_stress_test|cdb_stress_iteration_count is not defined"
)

for row in "${ROWS[@]}"; do
    IFS='|' read -r ID OP FILE KEY VALUE TESTPATH KFUNC EXPECT <<< "$row"
    LOG="$RESDIR/row_${ID}.log"
    echo "==================== ROW $ID ($KFUNC) ===================="

    # 1. perturb
    if [ "$OP" = "set" ]; then
        eval "$PB set \"$FILE\" \"$KEY\" '$VALUE'" || { echo "ROW $ID perturb FAILED" | tee -a "$SUMMARY"; continue; }
    else
        eval "$PB del \"$FILE\" \"$KEY\"" || { echo "ROW $ID perturb FAILED" | tee -a "$SUMMARY"; continue; }
    fi

    # 2. run the single test (expect FAIL). run_tests.sh wipes logs/, so capture
    #    its stdout to our own log under results/ (outside logs/).
    eval "$RUNBASE -c \"$TESTPATH\" -e \"--skip_sanity --skip_yang -k $KFUNC\"" > "$LOG" 2>&1

    # 3. revert (always)
    eval "$PB revert \"$FILE\"" >/dev/null

    # 4. judge
    RESULT_LINE=$(grep -E "[0-9]+ (passed|failed|error)" "$LOG" | tail -1)
    if echo "$RESULT_LINE" | grep -q "failed" && grep -qF "$EXPECT" "$LOG"; then
        VERDICT="PASS (failed as expected; msg matched)"
    elif echo "$RESULT_LINE" | grep -q "failed"; then
        VERDICT="PARTIAL (failed, but expected msg NOT found: '$EXPECT')"
    else
        VERDICT="NEGATIVE-FAIL (test did NOT fail)"
    fi
    printf "ROW %s  %-52s  %s\n" "$ID" "$KFUNC" "$VERDICT" | tee -a "$SUMMARY"
    printf "        result: %s\n" "${RESULT_LINE:-<none>}" | tee -a "$SUMMARY"
done

echo "==================== CLEANLINESS GATE ====================" | tee -a "$SUMMARY"
eval "$PB status" | tee -a "$SUMMARY"
