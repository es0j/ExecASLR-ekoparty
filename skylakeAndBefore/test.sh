#!/bin/bash
killall victim || echo "killing victim"
./victim &
./attacker 0x154 0x15d
echo "testing for leaked first half 0x31"
./attacker2 0x31154 0x15d 0x555000031000 0x56f000000000 0x135