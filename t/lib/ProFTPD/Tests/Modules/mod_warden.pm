package ProFTPD::Tests::Modules::mod_warden;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Data::Dumper;
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  warden_defaultroot_blacklisted_file_on_login => {
    order => ++$order,
    test_class => [qw(forking mod_warden rootprivs)],
  },

  warden_defaultroot_blacklisted_file_on_stor => {
    order => ++$order,
    test_class => [qw(forking mod_warden rootprivs)],
  },

  warden_defaultroot_blacklisted_file_on_rnto => {
    order => ++$order,
    test_class => [qw(forking mod_warden rootprivs)],
  },

  warden_defaultroot_blacklisted_file_on_site_cpto => {
    order => ++$order,
    test_class => [qw(forking mod_copy mod_warden rootprivs)],
  },

  warden_blacklisted_file_on_login => {
    order => ++$order,
    test_class => [qw(forking mod_warden)],
  },

  warden_anon_blacklisted_file_on_login => {
    order => ++$order,
    test_class => [qw(forking mod_warden rootprivs)],
  },

  # SFTP tests
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub warden_defaultroot_blacklisted_file_on_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:10',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Make sure the blacklisted file exists prior to connecting
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      # Make sure the blacklisted file exists prior to logging in
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      $client->login($user, $passwd);

      # Make sure the blacklisted file does NOT exist after logging in
      $self->assert(!-f $test_file,
        test_msg("Blacklisted file $test_file exists unexpectedly"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub warden_defaultroot_blacklisted_file_on_stor {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:10',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello, world!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($resp_code == $expected,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($resp_msg eq $expected,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Make sure the blacklisted file does NOT exist after STOR
      $self->assert(!-f $test_file,
        test_msg("Blacklisted file $test_file exists unexpectedly"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub warden_defaultroot_blacklisted_file_on_rnto {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $src_file = File::Spec->rel2abs("$tmpdir/src.txt");
  if (open(my $fh, "> $src_file")) {
    close($fh);

  } else {
    die("Can't open $src_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:20',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my ($expected, $resp_code, $resp_msg);

      ($resp_code, $resp_msg) = $client->rnfr('src.txt');

      $expected = 350;
      $self->assert($resp_code == $expected,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'File or directory exists, ready for destination name';
      $self->assert($resp_msg eq $expected,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      ($resp_code, $resp_msg) = $client->rnto('test.txt');

      $expected = 250;
      $self->assert($resp_code == $expected,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Rename successful';
      $self->assert($resp_msg eq $expected,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Make sure the blacklisted file does NOT exist after RNTO
      $self->assert(!-f $test_file,
        test_msg("Blacklisted file $test_file exists unexpectedly"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub warden_defaultroot_blacklisted_file_on_site_cpto {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $src_file = File::Spec->rel2abs("$tmpdir/src.txt");
  if (open(my $fh, "> $src_file")) {
    close($fh);

  } else {
    die("Can't open $src_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:20',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my ($expected, $resp_code, $resp_msg);

      ($resp_code, $resp_msg) = $client->site('CPFR', 'src.txt');

      $expected = 350;
      $self->assert($resp_code == $expected,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'File or directory exists, ready for destination name';
      $self->assert($resp_msg eq $expected,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      ($resp_code, $resp_msg) = $client->site('CPTO', 'test.txt');

      $expected = 250;
      $self->assert($resp_code == $expected,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Copy successful';
      $self->assert($resp_msg eq $expected,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Make sure the blacklisted file does NOT exist after SITE CPTO
      $self->assert(!-f $test_file,
        test_msg("Blacklisted file $test_file exists unexpectedly"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub warden_blacklisted_file_on_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:10',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Make sure the blacklisted file exists prior to connecting
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      # Make sure the blacklisted file exists prior to logging in
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      $client->login($user, $passwd);

      # Make sure the blacklisted file still exists after logging in,
      # since we are not chrooted
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub warden_anon_blacklisted_file_on_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/warden.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/warden.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/warden.scoreboard");

  my $log_file = test_get_logfile();

  my ($config_user, $config_group) = config_get_identity();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/warden.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/warden.group");

  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $config_user, 'foo', $uid, $gid, '/tmp',
    '/bin/bash');
  auth_group_write($auth_group_file, $config_group, $gid, $config_user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    close($fh);

  } else {
    die("Can't open $test_file: $!");
  }

  my $blacklist_file = File::Spec->rel2abs("$tmpdir/warden-blacklist.txt");
  if (open(my $fh, "> $blacklist_file")) {
    # The blacklisted path is the path to the file _as seen by the client_.
    print $fh "/test.txt\n";

    unless (close($fh)) {
      die("Can't write $blacklist_file: $!");
    }

  } else {
    die("Can't open $blacklist_file: $!");
  }

  my $config = {
    TraceLog => $log_file,
    Trace => 'warden:10',

    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    Anonymous => {
      $home_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',
      },
    },

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_warden.c' => {
        WardenEngine => 'on',
        WardenLog => $log_file,
        WardenBlacklist => $blacklist_file,
      },
    },
  };

  my ($port, $user, $group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Make sure the blacklisted file exists prior to connecting
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      # Make sure the blacklisted file exists prior to logging in
      $self->assert(-f $test_file,
        test_msg("Blacklisted file $test_file does not exist as expected"));

      $client->login($config_user, 'ftp@nospam.org');

      # Make sure the blacklisted file does NOT exist after logging in
      $self->assert(!-f $test_file,
        test_msg("Blacklisted file $test_file exists unexpectedly"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
