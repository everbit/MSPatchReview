# MSPatchReview
Query the MSRC API to pull information on Microsoft Patch Tuesday releases.

The code for this python script is a modified version of the script released by [Immersive Labs](https://github.com/Immersive-Labs-Sec/msrc-api). 

## Summary
This script can be used to query the Microsoft MSRC API to pull information on Microsoft Patch Tuesday releases. The script will output information on vulnerability types, severity, if there are any zero-days, exploited vulnerabilities, and vulnerabilities that are likely to be exploited to the terminal.

## Requirements
Requests

## Usage
PatchReview.py YYYY-MM
