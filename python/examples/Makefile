
AMPY := $(shell command -v ampy 2> /dev/null)
define AMPY_MISSING
ampy is not available on this system
It can be retrieved at
https://github.com/adafruit/ampy.git
endef
export AMPY_MISSING


all:
ifndef AMPY
	@echo "$$AMPY_MISSING" >&2
	$(error)
else
	make upload
endif

upload: uploadlib uploadExampleModules
	ampy -p /dev/ttyUSB0 put sensor.py /flash/main.py
	ampy -p /dev/ttyUSB0 reset
	echo -ne "import machine; machine.reset();\r" > /dev/ttyUSB0

uploadExampleModules:
	ampy -p /dev/ttyUSB0 put BMP280.py /flash/BMP280.py
	ampy -p /dev/ttyUSB0 put CBOR.py /flash/CBOR.py
	ampy -p /dev/ttyUSB0 put CoAP.py /flash/CoAP.py

uploadlib:
	ampy -p /dev/ttyUSB0 mkdir /flash/SCHC
	ampy -p /dev/ttyUSB0 put ../SCHC/__init__.py /flash/SCHC/__init__.py
	ampy -p /dev/ttyUSB0 put ../SCHC/BitBuffer.py /flash/SCHC/BitBuffer.py
	ampy -p /dev/ttyUSB0 put ../SCHC/Compressor.py /flash/SCHC/Compressor.py
	ampy -p /dev/ttyUSB0 put ../SCHC/Decompressor.py /flash/SCHC/Decompressor.py
	ampy -p /dev/ttyUSB0 put ../SCHC/Parser.py /flash/SCHC/Parser.py
	ampy -p /dev/ttyUSB0 put ../SCHC/RuleMngt.py /flash/SCHC/RuleMngt.py

login:
	screen -L /tmp/screenlog /dev/ttyUSB0 115200
