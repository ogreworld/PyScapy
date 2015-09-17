#setup.py


from setuptools import setup, find_packages
import PyScapy
from glob import glob

pcap_file = glob("PyScapy\\data\\packet\\*")

setup(name          = 'PyScapy',
      version       = PyScapy.__version__,
      description   = 'This is a package for dot11',
      packages      = find_packages(),
      data_files    = [('PyScapy\\data\\packet', pcap_file)],
      zip_safe      = False,
      )

