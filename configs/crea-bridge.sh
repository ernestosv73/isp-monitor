#!/bin/bash

# Crear bridge
brctl addbr br0
ip link set dev br0 up

# Agregar interfaces al bridge
brctl addif br0 eth1
