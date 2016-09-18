#!/usr/bin/python
import os
import sys
import json
import psycopg2
import psycopg2.extras
import gzip

from datetime import datetime

class ExistingTestInstance(Exception):
  pass

class NoSuchChallenge(Exception):
  pass

class NoSuchTeam(Exception):
  pass

class NoSuchTest(Exception):
  pass

db = psycopg2.connect("user=matthew dbname=perfwars")

def insert_test_instance(run, teamid, testid):
  cur = db.cursor()
  hostname = run['hostname']
  port = run['port']
  source_addr = run['source addresses']
  dest_addr = run['destination addresses']

  try:
    cur.execute("""INSERT INTO test_instances(
                   team_id, test_id, hostname, port, source_addresses,
                   destination_addresses
                 )
                 VALUES (
                   %s,%s,%s,%s,%s,%s
                 )
                 RETURNING id""",
                 (teamid, testid, hostname, port, source_addr, dest_addr))
  except psycopg2.IntegrityError:
    raise ExistingTestInstance
  i = cur.fetchone()[0]
  return i



def insert_rounds_and_connections(run, instance_id):
  cur = db.cursor()
  rids = []
  data = []
  for r in run['rounds']:
    x = (instance_id, r['concurrency'], r['realized concurrency'], 
         r['actual concurrency'],
         datetime.fromtimestamp(r['round start time']), 
         datetime.fromtimestamp(r['round end time']),
         datetime.fromtimestamp(r['connection completion time']),
         r['mean latency'], r['population standard deviation'], 
         r['distance from curve'], r['projected plot'],
         r['realized plot'], r['actual plot'])
    cur.execute("""INSERT INTO rounds(
                     test_id, concurrency, realized_concurrency, 
                     actual_concurrency, round_start, round_end,
                     connection_completion_time, mean_latency,
                     standard_deviation, distance_from_curve,
                     projected_plot, realized_plot, actual_plot
                   ) VALUES (
                      %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                   ) RETURNING id""", x)
    round_id = cur.fetchone()[0]
    for c in r['connections']:
      y = (round_id, c['source address'], c['destination address'],
           c['connection time'], c['ssl negotiation time'],
           c['first byte time'], c['transfer time'], c['total time'],
           c['state'], c['send buffer'], c['receive buffer'])
      cur.execute("""INSERT INTO connections (
                       round_id, source_address, destination_address,
                       connection_time, ssl_negotiation_time, first_byte_time,
                       transfer_time, total_time, state, send_buffer, 
                       receive_buffer
                     ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  """, y)
  return
  


def get_challenge_id(challenge):
  cur = db.cursor()
  cur.execute("SELECT id FROM challenges WHERE name=%s", (challenge,))
  row = cur.fetchone()
  if row == None:
    raise NoSuchChallenge("Challenge name cannot be found")
  i = row[0]
  return i



def get_team_id(teamname):
  cur = db.cursor()
  cur.execute("SELECT id FROM teams WHERE teamname=%s", (teamname,))
  row = cur.fetchone()
  if row == None:
    raise NoSuchTeam("The teamname given cannot be found")
  i = row[0]
  cur.close()
  return i

def get_test_id(seedname, chalid):
  cur = db.cursor()
  cur.execute("SELECT id FROM tests WHERE seedname=%s AND challenge_id=%s",
              (seedname, chalid))
  row = cur.fetchone()
  if row == None:
    raise NoSuchTest("The seedname given cannot be found")
  return row[0]



if __name__ == "__main__":

  if len(sys.argv) < 4:
    sys.stderr.write("Provide a challenge name, a team name, and a json gz file.\n")
    sys.exit(1) 

  teamname = sys.argv[2]
  challenge = sys.argv[1]
  if sys.argv[3].endswith("DONE"):
    sys.stderr.write("This file is already done. Skipping..\n")
    sys.exit(1)

  zf = gzip.GzipFile(sys.argv[3], "r")
  run = json.load(zf)

  ## Begin transaction
  teamid = get_team_id(teamname)
  chalid = get_challenge_id(challenge)
  testid = get_test_id(run['seed'], chalid)
  instanceid = insert_test_instance(run, teamid, testid)
  insert_rounds_and_connections(run, instanceid)
  db.commit()

  #os.rename(sys.argv[3], sys.argv[3]+".DONE")
