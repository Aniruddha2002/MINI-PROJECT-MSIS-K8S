@echo off

echo ==========================================
echo MACHINE LEARNING KUBERNETES SECURITY DEMO
echo ==========================================
echo.

echo [1] SECURE CLUSTER
echo ------------------------------------------
python ml\final_assessment.py reports\baseline\secure-config-features.csv

echo.
echo.
echo [2] KUBERNETES GOAT - INSECURE CLUSTER
echo ------------------------------------------
python ml\final_assessment.py reports\insecure\goat-config-features.csv

echo.
echo ==========================================
echo FINAL DEMO COMPLETE
echo ==========================================

pause