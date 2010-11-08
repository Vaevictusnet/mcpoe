#!/usr/bin/perl -w
use strict;
use POE;
use POE::Component::Client::TCP;
use POE::Filter::Stream;
use LWP::UserAgent;
use Data::Dumper;
use SMPConfig;
#use utf8;
#use encoding 'utf8';
use Encode qw(encode decode decode_utf8 encode_utf8 );
#use constant DEBUG=>1; # just functions/critical
#use constant DEBUG=>2; # just protocol packets
#use constant DEBUG=>4; # just parsing
#use constant DEBUG=>8; # just buffer updates
#use constant DEBUG=>16; # just buffer dumps
#use constant DEBUG=>32; # just informational (keepalives)
use constant DEBUG=>11; # no parsing problems...
#use constant DEBUG=>15; # 
#use constant DEBUG=>0; # 
#use constant DEBUG=>63; # everything
$Data::Dumper::Indent = 1;

############################################
# special warning handler
#
$SIG{__WARN__} = sub {
    warn @_;
    my $i = 0;
    while (my($pkg, $file, $line) = caller($i++)) {
      warn "  package $pkg, file $file, line $line\n";
    }
  }; 
$SIG{INT} = sub { 
  dump_protocol_score();
  die "killed...\n";
};
#
############################################

my @auth;
my $sock;
my $read_set;
my $sock_backbuf=undef;
my $serverkey='';
my $pm;
my $tickspeed= 0.1;
my $software_version=12;
my $protocol_version=3;
my $movecount = 0;
my $agent_header="Java/1.6.0_21";
my $entities = {};
my $reg;
my $ai;
my $pos;
my $got_teleport=0;

#$ai->{target} = 1;
#$ai->{started} = 0;
#$ai->{X} = -75;
#$ai->{Y} = 80;
#$ai->{Z} = 20;

$reg->{'relative_move'} = \&relative_move;
$reg->{'entity_teleport'} = \&entity_teleport;
$reg->{'relative_move_and_look'} = \&relative_move_and_look;
$reg->{'name_verification'} = \&name_verification;
$reg->{'chathandler'} = \&chathandler;
$reg->{'movehandler'} = \&movehandler;
$reg->{'startaimove'} = \&startaimove;
$reg->{'shutdown'} = \&shutdown;
$reg->{'named_entity_spawn'} = \&named_entity_spawn;
$reg->{'spawn_position'} = \&spawn_position;

my $config=SMPConfig::get();
load_protocol_data();
initialize_protocol_counters();
master_auth();

POE::Component::Client::TCP->new(
  RemoteAddress => $config->{host},
  RemotePort => $config->{port},
  Filter => "POE::Filter::Stream",

  ServerError => sub {
    debug(1,'Server error.');
    $_[KERNEL]->yield('shutdown');
  },
  Disconnected => sub {
    debug(1,'disconnected from server.');
    dump_protocol_score();
    $_[KERNEL]->yield('shutdown');
  },
  Connected => sub {
    debug(1,"connected...");
    $_[HEAP]->{packetbuffer} = [];
    $_[KERNEL]->yield('handshake');
  },
  ConnectError => sub { print "could not connect ... \n"; },
  ServerInput => sub {
    my ($kernel, $heap, $input) = @_[KERNEL, HEAP, ARG0];
    if($heap->{buf}) {
      $heap->{buf} .= $input;
    } else {
      $heap->{buf} = $input;
    }
    debug(8,'added '.length($input). ' bytes to buffer ('.length($heap->{buf}).')');
    debug(16,split(//,$heap->{buf}));
    byteparser($kernel,$heap);
  },

  InlineStates => {
    #parser => \&byteparser,
    AIMove => \&aimove,
    send_keepalive => sub {
      debug(32,"sending keepalive");
      $pm->{0x00}->{sent}++;
      if($_[HEAP]->{server})
      {
        $_[HEAP]->{server}->put( mcByte(0) );
        $_[KERNEL]->delay('send_keepalive',1);
      }
    },
    handshake => sub {
      $pm->{0x02}->{sent}++;
      debug(2,'sent handshake');
      $_[HEAP]->{server}->put( mcByte(2), mcStr($auth[2]));
    },
    request_login => sub {
      $pm->{0x01}->{sent}++;
      $_[HEAP]->{server}->put( 
        mcByte(1), # 0x01 packet
        mcInt($protocol_version),  # protocol version 
        mcStr($auth[2]), # username
        mcStr('Password'), # password
        mcLong(0),mcByte(0)
      );
      debug(2,'sent login');
    },
    input_timeout => sub {
      # remove?
      my ($kernel,$heap) = @_[KERNEL,HEAP];
      print "got input timeout ... \n";
      print ",----- returned code: \n";
      print join "",@{$heap->{packetbuffer}};
      print "`-----\n";
      $kernel->yield("shutdown");
    },
  },
  
);

$poe_kernel->run();
exit 0;

sub aimove {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  debug(8,"in aimove");
  return unless ( defined $ai && defined $ai->{'target'});
  my $d_x = $pos->{'X'} - $ai->{'X'};
  my $d_y = $pos->{'Y'} - $ai->{'Y'};
  my $d_z = $pos->{'Z'} - $ai->{'Z'};


  my $limit = 0.1; 
  foreach my $var ($d_x,$d_y,$d_z)
  {
    if($var > $limit) { $var = $limit; }
    elsif($var < -$limit) { $var = -$limit; }
  }
  # foreach my $var($d_x,$d_y,$d_z)
  # {
  #   if($var > 0) { $var = 100; }
  #   else { $var = -100; }
  # }
  
  debug(2,'making ai move:');
  debug(2,'  from   : ' .join(',',($pos->{'X'},$pos->{'Y'},$pos->{'Z'})));
  debug(2,'  towards: ' .join(',',($ai->{'X'},$ai->{'Y'},$ai->{'Z'})));
  debug(2,'  via    : ' .join(',',( $pos->{'X'}-$d_x,$pos->{'Y'}-$d_y,$pos->{'Z'}-$d_z)));

  $pos->{'X'} = $pos->{'X'}-$d_x;
  $pos->{'Y'} = $pos->{'Y'}-$d_y;
  $pos->{'Z'} = $pos->{'Z'}-$d_z;
  
  my @data;
  #push @data, $pos->{'X'}-$d_x, $pos->{'Y'}-$d_y,
  #$pos->{'Y'}-$d_y + 1.62, $pos->{'Z'}-$d_z,0,0,1;
  push @data, $pos->{'X'}, $pos->{'Y'}, $pos->{'Y'} + 1.62, $pos->{'Z'},0,0,1;
  #$d_x+$pos->{'X'},$d_y+$pos->{'Y'},0,$d_z + $pos->{'Z'},0;

  sendpacket($kernel,$heap,0x0d,@data);
#  sendpacket($kernel,$heap,0x0b,@data[0 .. 3,6]);
  sendpacket($kernel,$heap,0x0a,1);
  $movecount++;
  #sendpacket($kernel,$heap,0x03,("lol... moving. $movecount: $d_x,$d_y,$d_z|".join(",",@data)));
  $kernel->delay('AIMove',$tickspeed);

}

sub name_verification {
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  debug(1,'in name verify');
  my $serverkey = $args[2];
  if(!defined $serverkey) { die "couldn't find server key\n"; }
  debug(1,'server key: '.$serverkey);
  #debug(1,$serverkey);
  my $url = 'http://www.minecraft.net/game/joinserver.jsp';
  my $ua = LWP::UserAgent->new(agent=>$agent_header);
  $ua->timeout(60);
  $ua->env_proxy();

  my $data = {
    user => $auth[2],
    sessionId => $auth[3],
    serverId => $serverkey
    };

  my $response = $ua->post($url,$data);
  unless($response->is_success) { die $response->status_line; };
  unless($response->content =~ m/OK/i) { die "Couldn't get ok from mc.net: " .$response->content." \n"; }
  $kernel->yield("request_login");
}

sub sendpacket
{
#  print Dumper(@_); exit;
  my $kernel = shift;
  my $heap = shift;
  my $type = shift;
  my @args = @_;

  if($pm->{$type}) 
  {
    my $desc = $pm->{$type}->{type};
    my @pieces = split //,$pm->{$type}->{format};
    my @output;
    push @output, mcByte($type);

    foreach my $p (@pieces)
    {
      my $data = shift(@args);
      unless(defined($data)) { die("not enough data for $desc\n"); }
      if($p eq "b")
      {
        push @output, mcByte($data);
      }
      elsif($p eq "s")
      {
        push @output, mcShort($data);
      }
      elsif($p eq "i")
      {
        push @output, mcInt($data);
      }
      elsif($p eq "l")
      {
        push @output, mcLong($data);
      }
      elsif($p eq "f")
      {
        push @output, mcFloat($data);
      }
      elsif($p eq "d")
      {
        push @output, mcDouble($data);
      }
      elsif($p eq "S")
      {
        push @output, mcStr($data);
      }
      else
      {
        die("unsupported type $p, can't send $desc\n");
      }
    }

    my $bytes = join ('',@output);
    debug(2,"sent ".join('',unpack("H*",$bytes)));
    #debug(2,@output);

    if($heap && $heap->{server}) {
      $heap->{server}->put($bytes);
      $pm->{$type}->{sent}++;
      debug(2,"sent $desc");
    }
    else
    {
      debug(2,"dc'd");
      $kernel->yield("shutdown");
    }
  
    #$_[HEAP]->{server}->put( 
    #  mcByte(1), # 0x01 packet
    #  mcInt($protocol_version),  # protocol version 
    #  mcStr($auth[2]), # username
    #  mcStr('Password') #password
    #);
  }
  else
  {
    die("can't send type $type\n");
  }
}
sub startaimove
{
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  if(! $ai->{started} || $ai->{started} == 0) { 
    sendpacket($kernel,$heap,0x10,123,294); # holding a gold hoe :D
    $ai->{started} = 1;
    $kernel->yield("AIMove");
  }
}

sub entity_teleport {
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  debug(2,'entity teleport: '.$args[3]); 
  debug(2,'(X,Y,Z): ('.join(',',@args[1,2,3]).')');
  if($args[2] == $ai->{target})
  {
    $ai->{'X'} = $args[3];
    $ai->{'Y'} = $args[4];
    $ai->{'Z'} = $args[5];
  }
}

sub relative_move_and_look {
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  print STDERR Dumper(@args);
  debug(2,'relative entity move and look: '.$args[1]); 
  debug(2,'(X,Y,Z): ('.join(',',@args[2,3,4]).')');
  relative_move($kernel,$heap,$args[0],$args[1],$args[2],$args[3],$args[4]);
}
sub relative_move {
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  if($args[1] && $ai->{target} && $args[1] == $ai->{target})
  {
    $ai->{'X'} += $args[2];
    $ai->{'Y'} += $args[3];
    $ai->{'Z'} += $args[4];
  }
  print STDERR Dumper(@args);
  debug(2,'relative entity move: '.$args[1]); 
  debug(2,'(X,Y,Z): ('.join(',',@args[2,3,4]).')');
  #$ai->{'target'} = 1;
  #$ai->{'X'} = $args[1]/32;
}

sub movehandler 
{ 
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  my ($type,$x,$y,$stance,$z,$rotation,$pitch,$unk) = @args;
  debug(2,"player at $x,$y,$z\n");
  $pos->{'X'} = $x;
  $pos->{'Y'} = $y;
  $pos->{'Z'} = $z;

  # sanity check for notch's stupid typo:
  if($stance < $y) {
    sendpacket($kernel,$heap,$type,$x,$stance,$y,$z,$rotation,$pitch,$unk);
  } else {
    sendpacket($kernel,$heap,$type,$x,$y,$stance,$z,$rotation,$pitch,$unk);
  }

 # print Dumper($x);
 # print "\n";
  #$x += .1;
 # print Dumper($x);
  #print "\n";
  #exit;
  #sendpacket($kernel,$heap,$type,$x,$y,$stance,$z,$rotation,$pitch,$unk);
#  my $line = $args[2];
  #$line = colorize($line);
  #print $line."\n";
}


sub spawn_position
{ 
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  #my $kernel = shift;
  #my $heap = shift;
  #my @args = @_;
  print STDERR Dumper(@args);
  debug(2,'got named spawn: '.$args[3]); 
  debug(2,'(X,Y,Z): ('.join(',',@args[1,2,3]).')');
  #$ai->{'target'} = 1;
  #$ai->{'X'} = $args[1]/32;
  #$ai->{'Y'} = $args[2]/32;
  #$ai->{'Z'} = $args[3]/32;
  $pos->{'X'} = $args[1]/32;
  $pos->{'Y'} = $args[2]/32;
  $pos->{'Z'} = $args[3]/32;
  #$kernel->delay('AIMove',$tickspeed); # queue AI movement in one half second
}

sub named_entity_spawn
{ 
  #my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  my $kernel = shift;
  my $heap = shift;
  my @args = @_;
  #print STDERR Dumper(@args); exit;
  if($args[3] eq 'Vaevictus')
  {
    $ai->{'target'} = $args[2];
    $ai->{'X'} = $args[4]/32;
    $ai->{'Y'} = $args[5]/32;
    $ai->{'Z'} = $args[6]/32;
    $kernel->delay('AIMove',$tickspeed); # queue AI movement in one half second
  }
  debug(2,'got named spawn: '.$args[3]); 
  debug(2,'#id (X,Y,Z): #'.$args[2].' ('.join(',',@args[4,5,6]).')');
  #print STDERR Dumper(@args);
  #print STDERR 'iSiiibbs';
  #exit;
#  my $line = $args[2];
#  $line = colorize($line);
# print $line."\n";
}

sub chathandler 
{ 
  my ($kernel, $heap, @args) = @_[0,1,2 .. $#_];
  #print STDERR Dumper(@args); exit;
  debug(2,'got chat: '.$args[2]); 
  my $line = $args[2];
  if($line =~ m/^<Vaevictus>\s/)
  {
    my ($cmd) = $line =~ m/^<Vaevictus>\s(.*)/;
    if($cmd eq "stop")
    {
      $ai->{target} = undef;
    }
    elsif($cmd eq "come here")
    {
      #retarget $ai to point
    }
    elsif($cmd eq "follow")
    {
      #retarget $ai to entity 
    }
    elsif($cmd eq "quit")
    {
      sendpacket($kernel,$heap,0x03,(";_;"));
      sendpacket($kernel,$heap,0xFF,("QUIT"));
      $kernel->yield("shutdown");
    }

  }
  $line = colorize($line);
  print STDERR $line."\n";
  print $line."\n";
}


sub colorize
{
  my $line =shift;
  my %map = (
    '§0' => "\e[30;47m", #black
    '§1' => "\e[34;40m", #blue
    '§2' => "\e[32;40m", #green
    '§3' => "\e[36;40m", #cyan
    '§4' => "\e[31;40m", #red
    '§5' => "\e[35;40m", #magenta
    '§6' => "\e[33;40m", #yellow
    '§7' => "\e[37;40m", #white
    '§8' => "\e[1;30;47m", #black
    '§9' => "\e[1;34m", #blue
    '§a' => "\e[1;32m", #green
    '§b' => "\e[1;36m", #cyan
    '§c' => "\e[1;31m", #red
    '§d' => "\e[1;35m", #magenta
    '§e' => "\e[1;33m", #yellow
    '§f' => "\e[1;37m", #white
  );

  if($line =~ m/§\w/)
  {
    foreach my $key (keys %map)
    {
      my $c = $map{$key};
      $line =~ s/$key/$c/g;
    }
    $line .= "\e[0m";
  }
}
sub byteparser
{
  my ($kernel, $heap) = @_;
  my $cont = 1;

  while($cont && defined($heap->{buf}) && length($heap->{buf})) {
    my $buf = $heap->{buf};
    
    #debug(4,"*s0* parser");

    return unless($buf);
    #debug(4,"*s1* parser");
    return unless length($buf) > 0;

    #debug(4,"*s2* parser");

    my $type = unpack("C",$buf);
    if($type == 0)
    {
      debug(32,"received (0x00) keepalive"); # not a #2 because it might get noisy
      score($type);
      $heap->{buf} = substr($buf,1);
      next;
      #byteparser($kernel,$heap);
      #return;
    }
    
    unless($pm->{$type})
    {
      die "unknown packet type: '$type'\n";
    }

    my $p = $pm->{$type};
    debug(2,"received ".$p->{type} . " (" . $pm->{$type}->{rec} . ")");

    score($type);

    my $formula = 'C';
    my $p_size = 1; # start plus type
    foreach my $unit (split //,$p->{format})
    {
      debug(4,"formula: ($formula)\t\tsize: ($p_size)\t\t unit: ($unit)");
      if($unit eq 'b')
      {
        $formula .= 'C';
        #$formula .= 'c';
        $p_size += 1;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 's')
      {
        #$formula .= 'n';
        $formula .= 's>';
        $p_size += 2;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 'i')
      {
        #$formula .= 'N>';
        $formula .= 'l>';
        $p_size += 4;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 'l')
      {
        $formula .= 'N2';
        #$formula .= 'q>'; unsupported
        $p_size += 8;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 'S')
      {
        unless( length($buf) >= $p_size + 2) { debug(4,'failed string 1'); return; }
        debug(4,"string pos: ($p_size)");
        my $strsz = unpack("\@$p_size n",$buf);
        $p_size += 2;  # 2
        $p_size += $strsz;
        $formula .= "na$strsz";
        debug(4,"string size: ($strsz)");
        debug(16,split(//,$buf));
        unless( length($buf) >= $p_size) { debug(4,'failed string 2'); return; }
      }
      elsif($unit eq 'f')
      {
        #$formula .= 'N';
        $formula .= 'f>';
        $p_size += 4;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 'd')
      {
        #$formula .= 'N2';
        $formula .= 'd>';
        $p_size += 8;
        return unless length($buf) >= $p_size;
      }
      elsif($unit eq 'X')
      {
        unless( length($buf) >= $p_size + 4) { debug(4,'failed chunk 1'); return; }
        debug(4,"string pos: ($p_size)");
        my $strsz = unpack("\@$p_size N",$buf);
        $p_size += 4;  # 2
        $p_size += $strsz;
        $formula .= "Na$strsz";
        debug(4,"string size: ($strsz)");
        debug(16,split(//,$buf));
        unless( length($buf) >= $p_size) { debug(4,'failed chunk 2'); return; }
      }
      elsif($unit eq 'I')
      {
        # short (length) of
        # { short [byte short] }
        #multi byte change shout, 3 arrays (short, byte, byte)
        # read payload count (short)
        unless( length($buf) >= $p_size + 2) { debug(4,'failed inventory 1'); return; }
        debug(4,"string pos: ($p_size)");
        my $strsz = unpack("\@$p_size s>",$buf); # array length
        $p_size += 2;  # 2
        $formula .= 's>';
        debug(4,"payload size: ($strsz)");

        foreach my $index ( 1 .. $strsz )
        {
          # foreach payload piece, load a short to see if it's -1
          unless( length($buf) >= $p_size + 2) { debug(4,'failed inventory 2'); return; }
          debug(4,"-- string pos: ($p_size)");
          my $val = unpack("\@$p_size s>",$buf); # array length
          debug(4,"---- id: ($val)");
          $p_size += 2;  # 2
          $formula .= 's>';
          
          unless($val == -1)
          {
            unless( length($buf) >= $p_size + 3) { debug(4,'failed inventory 3'); return; }
            $formula .= 'bs>';
            $p_size += 3;
          }
        }

      #  debug(4,"string size: ($strsz)");
      #  debug(16,split(//,$buf));
      }
      elsif($unit eq 'M')
      {
        #multi byte change - short, 3 arrays (short, byte, byte)
        unless( length($buf) >= $p_size + 2) { debug(4,'failed mbc 1'); return; }
        debug(4,"string pos: ($p_size)");
        my $strsz = unpack("\@$p_size n",$buf);
        $p_size += 2;  # 2
        $p_size += $strsz * 4;
        my $dbsz = $strsz * 2;
        $formula .= "N a$dbsz a$strsz a$strsz";
        debug(4,"string size: ($strsz)");
        debug(16,split(//,$buf));
        unless( length($buf) >= $p_size) { debug(4,'failed mbc 2'); return; }
      }
      else
      {
        die "unknown unit type: '$unit'\n";
      }
        
    }
    debug(4,"successful parse: ($type) $formula");

    my @pieces = unpack($formula,$buf);
    #$heap->{data} = \@pieces;
    #print STDERR Dumper(@pieces);

    if(length($buf) > $p_size) {
      $heap->{buf} = substr($heap->{buf},$p_size);
      debug(16,split(//,$heap->{buf}));
      #byteparser($kernel,$heap);#$kernel->yield("parser");
      # next; < -- breaks posts...
    } else {
      $heap->{buf} = undef;
      debug(8,'consumed entire buffer');
      $cont = 0;
    }

    if($p->{post})
    {
      debug(1,'found post for '.$p->{post});
      if($p->{post} eq 'shutdown') {
        $kernel->yield('shutdown');
      }
      else
      {
        &{$reg->{$p->{post}}}($kernel,$heap,@pieces);
      }
      #$kernel->yield($p->{post},@pieces);
    }

    if($p->{delay})
    {
      debug(1,'found delay: ' . $p->{delay}->{name});
      $kernel->delay($p->{delay}->{name},$p->{delay}->{value});
    }
  }
}

sub master_auth
{
  my @url = (
    'http://www.minecraft.net/game/getversion.jsp',
    'http://www.minecraft.net/resources/'
  );
  my $ua = LWP::UserAgent->new(agent=>$agent_header);

  $ua->timeout(60);
  $ua->env_proxy();

  my $data = {
    user => $config->{username},
    password => $config->{password},
    version => $software_version
  };

  my $response = $ua->post($url[0],$data);

  unless($response->is_success) { die $response->status_line; };

  my $authstring = $response->content;

      #
      # the client asks for resources... we can ignore them,
      # or skip this probably. 
      #

  $response = $ua->get($url[1]);
  @auth = split /:/,$authstring;
  
  my @logauth = ($auth[0],$auth[1],$auth[2],$auth[3]); 
  $logauth[1]=~s/\w(\w)/*$1/g;
  $logauth[2]=~s/\w/*/g;
  $logauth[3]=~s/\w/*/g;
  debug(1,"started @ ".localtime(time));
  debug(1, "current version: $logauth[0]\ndownload ticket: $logauth[1]\nusername: $logauth[2]\nsession id:$logauth[3]");

}


sub debug
{
  my $level = shift;
  my @msgs = @_;
  my $hexmode = ($#msgs > 0);

  if(! defined $level) { $level = 1; }
  if((DEBUG & $level) > 0 )
  {
    if($hexmode) {
      #print STDERR $level . ' ';
      print STDERR ' ';
      my $ascii='';
      
      foreach my $msg_idx (0 .. $#msgs)
      {
        my $msg = $msgs[$msg_idx];
        printf STDERR "%02x",ord($msg);
#        print STDERR "|$msg";
        if($msg=~m/[^[:print:]]/)
        {
          $ascii.='.';
        }
        else
        {
          $ascii .= $msg;
        }

      #  print "\nl(".length($msg).")\n";

        if($msg_idx == 0) 
        {
          print STDERR " ";
        #  $ascii='';
        }
        elsif(($msg_idx+1) % 16 == 0 || $msg_idx == $#msgs)
        {
          my $position = 50;
          my $offset = ($position - (($msg_idx+1)%16)*3) % $position ;
          my $gap = ' ' x $offset;
          print STDERR "$gap |$ascii|\n";
          #print STDERR "$gap |$ascii|\n$level ";
          #print STDERR "(offset $offset)\n";
          $ascii='';
        }
        elsif(($msg_idx+1)%8 == 0)
        {
          print STDERR " - ";
        }
        else
        {
          print STDERR " ";
        }

      }
    }
    else # msg mode
    {
      #print STDERR $level.' '.$msgs[0]; 
      print STDERR $msgs[0]; 
    }
    print STDERR "\n";
  }
}

######################################################
# create client to server bytes...
#
sub mcByte
{
  my $input=shift;
#  debug(2,"packing $input as byte");
#  debug(2,"packing $input as ".join('',unpack("H*",pack("c",$input))));
  return pack("c",$input);
}

sub mcShort
{
  my $input=shift;
  return pack("s>",$input);
  #return pack("n",$input);
}

sub mcDouble
{
  my $input = shift;
#  debug(2,"packing $input as double");
#  debug(2,"packing $input as ".join('',unpack("H*",pack("d>",$input))));

  return pack("d>",$input);
}

sub mcFloat
{
  my $input = shift;
  return pack("f>",$input);
}

sub mcLong
{
  my $input = shift;
  return pack("q>",$input);
  #return pack("N2",$input);
}

sub mcInt
{
  my $input = shift;
  return pack("l>",$input);
  #return pack("N",$input);
}

sub mcStr
{
  my $input = shift;

  $input = encode_utf8($input);

  my $len = length($input);
  my $val = mcShort($len);

  $val .= $input;
  #print Dumper(encode_utf8($input));
  
  #$val .= pack("W$len",$input);
  #print Dumper($val); exit;
  return $val;
}
# 
##################################################

sub initialize_protocol_counters
{
  foreach my $key (keys %$pm)
  {
    $pm->{$key}->{rec}=0;
    $pm->{$key}->{sent}=0;
  }
}

sub score
{
  my $type=shift;
  if($type == 0)
  {
    $pm->{$type}->{rec}++;
  }
  elsif(defined $pm->{$type})
  {
    $pm->{$type}->{rec}++;
  }
  else
  {
    die "unknown type: $type\n"; 
  }
    
}

sub dump_protocol_score
{
  debug(2,"############# received packets ####################");
  foreach my $key (sort keys %$pm)
  {
    if($pm->{$key}->{rec} > 0)
    {
      debug(2,$pm->{$key}->{type}.": ". $pm->{$key}->{rec});
    }
  }
  debug(2,"############# sent packets ####################");
  foreach my $key (sort keys %$pm)
  {
    if($pm->{$key}->{sent} > 0)
    {
      debug(2,$pm->{$key}->{type}.": ". $pm->{$key}->{sent});
    }
  }
}

sub load_protocol_data
{
#LOAD
  $pm = {
    0x00 => {
      format => "",
      type=>"keepalive",
    },
    0x01 => {
      format => "iSSlb",
      #delay => { name => "shutdown", value => "10" },
      type => "login",
    },
    0x02 => {
      type => "handshake",
      format => "S",
      post => "name_verification",
      #delay => { name => "AIMove", value =>"3"},
    }, 
    0x03 => {
      type => "chat",
      format => "S",
      post => "chathandler",
    }, 
    0x04=>{
      type=>"update time",
      format=>"l",
    },
    0x05=>{
      type=>"update inventory",
      format=>"iI",
    },
    0x06=>{
      type=>"spawn position",
      format=>"iii",
      post=>"spawn_position",
    },
    0x0a=>{
      type=>"onground", # unknown...
      format=>"b"
    },
    0x0b=>{
      type=>"player position",
      format=>"ddddb"
    },
    0x0c=>{
      type=>"player look",
      format=>"ffb"
    },
    0x0d=>{
      type=>"player move and look",
      format=>"ddddffb",
      post=>"movehandler",
      #delay=> { name => "AIMove" , value => "3" },
    },
    0x0e=>{
      type=>"block dig",
      format=>"bibib"
    },
    0x0f=>{
      type=>"place block/item",
      format=>"sibib"
    },
    0x10=>{
      type=>"block/item switch",
      format=>"is",
    },
    0x11=>{
      type=>"add to inventory",
      format=>"sbs",
    },
    0x12=>{
      type=>"arm animation",
      format=>"ib",
    },
    0x14=>{
      type=>"named entity spawn",
      format=>'iSiiibbs',
      post=>"named_entity_spawn",
    },
    0x15=>{
      type=>"entity spawn",
      format=>'isbiiibbb',
    },
    0x16=>{
      type=>'collect item',
      format=>'ii',
    },
    0x17=>{
      type=>'vehicles',
      format=>'ibiii',
    },
    0x18=>{
      type=>'mob spawn',
      format=>'ibiiibb',
    },
    0x1d=>{
      type=>'destroy entity',
      format=>'i',
    },
    0x1e=>{
      type=>'entity',
      format=>'i',
    },
    0x1f=>{
      type=>'relative entity move',
      format=>'ibbb',
      post=>'relative_move',
    },
    0x20=>{
      type=>'entity look',
      format=>'ibb',
    },
    0x21=>{
      type=>'relative entity move + look',
      format=>'ibbbbb',
      post=>'relative_move_and_look',
    },
    0x22=>{
      type=>'entity teleport',
      format=>'iiiibb',
      post=>'entity_teleport',
    },
    0x32=>{
      type=>'pre-chunk',
      format=>'iib',
    },
    0x33=>{
      type=>'map chunk',
      format=>'isibbbX',
      post => 'startaimove',
    },
    0x34=>{
      type=>'multi block change',
      format=>'iiM',
    },
    0x35=>{
      type=>'block change',
      format=>'ibibb',
    },
    0x3b=>{
      type=>'chest/sign',
      format=>'isiS',
    },
    0xff=>{
      type=>'client disconnect',
      format=>'S',
      post=>'shutdown',
    }
  };
}

########################################################################

