#!/usr/bin/env bash

TESTCASE_DIR=$1
IMAGE_FILE=exfat.img
FSCK_PROG=../build/sbin/fsck.exfat
FSCK_OPTS=-y
PASS_COUNT=0

cleanup() {
	echo ""
	echo "Passed ${PASS_COUNT} of ${TEST_COUNT}"
	exit
}

if [ $# -eq 0 ]; then
	TESTCASE_DIRS=$(find . -mindepth 1 -maxdepth 1 -type d)
	TEST_COUNT=$(find . -mindepth 1 -maxdepth 1 -type d | wc -l)
else
	TESTCASE_DIRS=$@
	TEST_COUNT=$#
fi

for TESTCASE_DIR in $TESTCASE_DIRS; do
	if [ ! -e "${TESTCASE_DIR}/${IMAGE_FILE}.tar.xz" ]; then
		TEST_COUNT=$((TEST_COUNT - 1))
		continue
	fi

	echo "Running ${TESTCASE_DIR}"
	echo "-----------------------------------"

	# Set up image file as loop device
	tar -C . -xf "${TESTCASE_DIR}/${IMAGE_FILE}.tar.xz"
	DEV_FILE=$(losetup -f "${IMAGE_FILE}" --show)

	# Run fsck for repair
	$FSCK_PROG $FSCK_OPTS "$DEV_FILE"
	if [ $? -ne 1 ]; then
		echo ""
		echo "Failed to repair ${TESTCASE_DIR}"
		losetup -d "${DEV_FILE}"
		cleanup
	fi

	echo ""
	# Run fsck again
	$FSCK_PROG -n "$DEV_FILE"
	if [ $? -ne 0 ]; then
		echo ""
		echo "Failed, corrupted ${TESTCASE_DIR}"
		losetup -d "${DEV_FILE}"
		cleanup
	fi

	if [ -e "${TESTCASE_DIR}/exfat.img.expected.xz" ]; then
		EXPECTED_FILE=${IMAGE_FILE}.expected
		unxz -cfk "${TESTCASE_DIR}/${EXPECTED_FILE}.xz" > "${EXPECTED_FILE}"
		diff <(xxd "${IMAGE_FILE}") <(xxd "${EXPECTED_FILE}")
		if [ $? -ne 0 ]; then
			echo ""
			echo "Failed ${TESTCASE_DIR}"
			losetup -d "${DEV_FILE}"
			cleanup
		fi
	fi

	echo ""
	echo "Passed ${TESTCASE_DIR}"
	PASS_COUNT=$((PASS_COUNT + 1))

	losetup -d "${DEV_FILE}"
done
cleanup
