<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
      <section id="no-signed-key">
<h1>Congrats and welcome to <b>Keysas</b></h1>
<p> My IP is {{ ip[0] }}.</p>
<p><b>KEYSAS</b> is 100% opesource and written in Rust :-) <br> The provided SD card image for Raspberry Pi 4 is based a hardened GNU/Linux Debian 12 (Bookworm). DHCP is activated by default: your IP should available above in this page.</p>
<p> If your are using the SD image, we already have configured protections against BadUSB, only USB mass storages will be recognized. USB keyboards and mouse should <b>not</b> work.</p>
To administrate your <b>Keysas</b> stations, you should install the <b>Keysas-admin</b> application on a dedicated administration laptop (Debian 12). This app is available at github.com/keysas-fr/keysas/ then click on <b>Releases</b> section.
<div class="callout callout-warning">
If it's your first time using <b>Keysas-admin</b>, you should start by generating a <b>IKPQPKI</b> (<b>I</b>ncredible <b>K</b>eysas <b>P</b>ost-<b>Q</b>uantum <b>P</b>rivate <b>K</b>ey <b>I</b>nfrastrcture) using <b>Keysas-admin</b>, enroll your new <b>Keysas</b> station and sign at least one output USB device. <br>
</div>
<p>Unsigned USB devices will be automatically considered as untrusted whereas signed USB devices using <b>Keysas-admin</b> will be considered trusted to retrieve your documents.
This following HOW-TO shows you how to sign a new USB device.</p>
<h2>Keysas-admin</h2>
<section id="creation-pki">
<h3>1 - PKI creation</h3>
This procedure will show you how to generate a new hybrid (Ed25519/Ditithium5) PKI to sign both trusted USB devices and your documents in the <b>Keysas</b> reports (.krp).
<div class="callout callout-info">
  If no PKI were previously created, go to <b>Keysas-admin</b>, then go to <b>Admin configuration</b> and click on <b>IKPQPKI configuration</b>. <br>
  Click on <b>Create a new IKPQPKI</b> and provide the parameters you want to customize your PKI. 
</div> 
<p>The key generation might take a while, so be patient :o)</p>
<div class="callout callout-danger">
  The chosen password strengh must be as strong as you can and the password must be saved securely.<br>
Do not loose or forget your password or the PKI will be unrecoverable. 
  </div>
  <div class="callout callout-info">
    By default, private keys are stored using the <b>PKCS#8</b> format and the public key using the <p>PEM</p> format. <br>
    On the <b>Keysas</b>, they are all stored under /etc/keysas/ path.
    </div>
</section>

<section id="generation-des-cles-de-signature">
<h3>2 - Add a new Keysas station</h3>
  <p>Add now a new <b>Keysas</b> station using <b>Keysas-admin</b> by clicking on <b>"Add a Keysas"</b>. Provide a name and an IP address.</p>
  <div class="callout callout-info">
  The remove administration is done using <b>SSH</b>. It is necessary to create an SSH keypair using <b>Ed25519</b> format only on the <b>admin</b> computer to allow <b>Keysas-admin</b> application to securely connect your remote <b>Keysas</b> stations.
  </div>
<p>To do so, open a terminal and type:<b></b></p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">ssh-keygen -m PEM -t ed25519 -f mykey</span>
</code></pre></div>
<p>Then go to <b>Admin configuration/SSH configuration</b> and provide the path to your public and private keys. Go to <b>Manage your Keysas</b> and click on <b>Export SSH pubkey</b>. Note that the path /home/keysas/.ssh must be present (for custom installations). Then wait until the status become <b class="text-success">Online</b>. Click on <b>More...</b> and <b>Enroll</b> to generate the remote keys on the <b>Keysas</b> station.</p>


</section>
<section id="signature-d-un-peripherique-usb">
<h3>3 - Sign a USB key</h3>
<p> To sign a new trusted key, go to administration menu and choose <b>"Sign a key"</b>. Provide your <b>IKPQPKI</b> password and click on <b class="text-success">Sign</b>.<br>
Plug your USB key in a USB port and wait for the confirmation message. That's all !</p>

<div class="callout callout-info">
  Every signed device will recognized on any <b>Keysas</b> station enrolled with you <b>IKPQPKI</b>. 
</div>

<p>You must now format your newly signed device (ext2, ext3, ext4, fat32, exfat, ntfs) using mkfs.* for example.</p>

<p>For more documentation, visit <b>keysas.fr</b>.</p>
</section>
</section>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "AppWizard-en",
  props: {
    ip: [],
  },
};
</script>

<style lang="scss">
@import "../assets/style/app.scss";

pre {
  background: $navy;
  color: $grey-light;
  padding: 5px;
  border-radius: 2px;
}

#no-signed-key {
  padding: 40px;
}

</style>
