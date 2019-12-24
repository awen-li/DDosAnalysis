#  !bash

base_dir=`pwd`

#1. output directory
mkdir output

#2. build analysis tool
make clean; make; cp dosAnalysis ./output

#3. build gs attacker
cd tool/gsattack; make clean; make; make; cp gsattack $base_dir/output; cd -

#4. build ied tool
cd tool/libiec61850/examples/test; make clean; make; 
cp ied1 ied2 IEC_Net.py run.sh -f $base_dir/output; cd -




