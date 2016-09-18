<?php
define("SHA256_KEY", "CALL_ME_DADDY"); // < --- WARNING WARNING THIS KEY IS INVALID FOR THE REAL TASK


/* Sends a not found message to a URI */
function not_found(
    $msg)
{
  header($_SERVER['SERVER_PROTOCOL']." 404 Not Found");
  header("Content-Type: text/plain");
  echo "404 Not Found\n";
  echo "$msg";
  exit();
}

function forbidden(
    $msg)
{
  header($_SERVER['SERVER_PROTOCOL']." 403 Forbidden");
  header("Content-Type: text/plain");
  echo "403 Forbidden\n";
  echo "$msg";
  exit();
}


function scan_dir_for_hashes(
    $dir,
    $name)
{
  $olddir = getcwd();
  if (chdir($dir) == FALSE) {
    not_found("No dynamic directory\n");
  }

  $files = scandir(".", SCANDIR_SORT_NONE);

  /* Scan the static files to see if it contains the correct sha sum */
  foreach ($files as $fn) {
    /* Skip dirs */
    if (is_dir($fn) == TRUE) {
      continue;
    }

    /* Open this file */
    $f = fopen($fn, "r");
    if ($f == FALSE) {
      not_found("");
    }

    /* Calculate the sha sum */
    $sha = hash_init("sha256");
    hash_update($sha, SHA256_KEY);
    while (!feof($f)) {
      hash_update($sha, fread($f, 16));
    }
    $h = hash_final($sha);

    /* When we get a match, pass the data to the user */
    fseek($f, 0, SEEK_END);
    $datalen = ftell($f);
    fseek($f, 0, SEEK_SET);
    if ($h == $name) {
      fseek($f, 0, SEEK_SET);
      header("Content-Type: application/octet-stream");
      header("Content-Disposition: attachment; filename=\"$fn\"");
      header("Content-Length: ".$datalen);
      while (($data = fread($f, 16)) == TRUE) {
        echo $data;
      }
      fclose($f);
      exit();
    }

    /* Close up and retry */
    fclose($f);
  }

  chdir($olddir);
}


/* Performs a static file retrieval */
function handle_file(
    $uri)
{
  if (preg_match('/\.\./', $uri) == TRUE) {
    not_found("");
  }

  $name=basename($uri);

  chdir("static");
  $f = fopen($name, "r");
  if ($f == FALSE) {
    chdir("../dynamic");
    $f = fopen($name, "r");
    if ($f == FALSE) {
      not_found();
    }
  }
  

  $sha = hash_init("sha256");
  hash_update($sha, SHA256_KEY);
  $data = "";
  while (!feof($f)) {
    $data .= fread($f, 16);
  }
  hash_update($sha, $data);
  $h = hash_final($sha);
  header("Content-Type: text/plain");
  echo "$h\n";
  fclose($f);
}



/* Determines the filename behind a static sha256 sum and returns file */
function handle_sha(
     $uri)
{
  $name = basename($uri);
  /* Scan the static files to see if it contains the correct sha sum */
  scan_dir_for_hashes('static', $name);

  /* No joy, switch into the submitted files instead */
  scan_dir_for_hashes('dynamic', $name);
  not_found("");
}


/* Saves new key/data combination. Returns the sha256sum */
function handle_post(
    $uri)
{
  $name = basename($uri);
  if (isset($_POST['data']) == FALSE) {
    not_found(print_r($_POST));
  }

  chdir('dynamic');
  $data = $_POST['data'];
  $length = strlen($data);
  $f = fopen($name, "w");
  for ($i=0; $i < $length; $i += 16) {
    $snippet = substr($data, $i, ($length - $i) < 16 ? ($length - $i) : 16);
    fwrite($f, $snippet);
  }
  fclose($f);

  $h = hash("sha256", SHA256_KEY.$data);
  header("Content-Type: text/plain");
  echo $h."\n";
}




$uri=$_SERVER['REQUEST_URI'];

if ($_SERVER['REQUEST_METHOD'] == "GET" or $_SERVER['REQUEST_METHOD'] == 'HEAD') {

  if (preg_match('/^\/file\/[a-zA-Z0-9_\.]+$/', $uri) == TRUE) {
    handle_file($uri);
  }

  else if (preg_match('/^\/sha\/[0-9a-f]{64}$/', $uri) == TRUE) {
    handle_sha($uri);
  }

  else{
    not_found("");
  }
}
else if ($_SERVER['REQUEST_METHOD'] == 'POST') {

  if (preg_match('/^\/submit\/[a-zA-Z0-9_\.]{3,32}$/', $uri) == TRUE) {
    handle_post($uri);
  }
  else if (preg_match('/^/submit\/.*/', $uri) == TRUE) {
    forbidden("");
  }
  else {
    not_found("");
  }
}

?>
