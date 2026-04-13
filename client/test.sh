#!/bin/bash


rep_subject_credentials poop credentials.json
sleep 1

rep_create_org Poop_Factory Poop_Master Tiago Poop@factory.com credentials.json
sleep 1

rep_list_orgs
sleep 1

rep_create_session Poop_Factory Poop_Master poop credentials.json session.json

