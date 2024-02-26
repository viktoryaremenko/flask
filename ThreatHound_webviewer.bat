@echo off

if exist ./venv_ThreatHound (
	echo Virtual environment already exists.
    call venv_ThreatHound\Scripts\activate.bat
) else (
    python -m venv venv_ThreatHound
	call venv_ThreatHound\Scripts\activate.bat
	python -m pip install pip --upgrade
	python -m pip install --upgrade -r requirements_ThreatHound.txt --ignore-installed
)

python ThreatHound_v2.py -r
pause