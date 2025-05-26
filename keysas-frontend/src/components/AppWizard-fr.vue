<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
      <section id="no-signed-key">
<h1>Félicitations et bienvenue sur <b>Keysas</b></h1>
<p> Mon ip est {{ ip[0] }}.</p>
<p><b>KEYSAS</b> est une solution de station blanche 100% opensource et écrite en Rust :-) <br> L’image fournie pour Raspberry Pi 4 est basée sur une distribution GNU/Linux Debian 12 (Bookworm) durcie. Le DHCP est activé par défaut: l’adresse IP obtenue est normalement affichée plus haut.</p>
<p>Afin de prémunir la station blanche d’attaques de type BadUSB, seuls les périphériques USB de type “stockage de masse” comme les clés ou disques durs USB sont reconnus par la station blanche. Les claviers USB et les souris ne peuvent donc <b>pas</b> fonctionner.</p>
Pour pouvoir administrer vos stations blanches <b>Keysas</b>, vous devez d'abord installer l'application <b>Keysas-admin</b> sur un poste d'administration
GNU/Linux dédié (Debian 12). Cette application est disponible en téléchargement sur github.com/keysas-fr/keysas/ dans la rubrique <b>Releases</b> au format .deb.
<div class="callout callout-warning">
Si c'est la première fois que vous utilisez une station blanche <b>Keysas</b>, vous devez commencer par générer une <b>IKPQPKI</b> (<b>I</b>ncredible <b>K</b>eysas <b>P</b>ost-<b>Q</b>uantum <b>P</b>rivate <b>K</b>ey <b>I</b>nfrastrcture) avec <b>Keysas-admin</b>, enroller la nouvelle station blanche et signer un(des) périphérique(s) USB de sortie. <br>
</div>
<p>En effet, toutes les clés non signées seront considérées comme des clés d'entrée et les clés signées par <b>Keysas-admin</b> seront considérées comme clés de sortie par la station blanche. Seules les clés de sortie permettent la récupération des fichiers signés.
Ce tutoriel va vous montrer comment procéder. Vous pourrez le ré-afficher à tout moment en utilisant le menu en haut à droite.</p>
<h2>Keysas-admin</h2>
<section id="creation-pki">
<h3>1 - Création de la PKI de signature</h3>
Cette procédure vous permettra de générer une PKI hybride Ed25519-Ml-Dsa-87 (IKPQPKI) pour la signatures des clés de sortie et la signature des documents passés dans une station blanche <b>Keysas</b>.
<div class="callout callout-info">
  Si vous n'avez jamais créé de PKI avec <b>Keysas-admin</b>, il suffit lancer l'application puis d'aller sur <b>Admin configuration</b> et de cliquer sur <b>IKPQPKI configuration</b>. <br>
  Cliquez ensuite sur <b>Create a new IKPQPKI</b> puis entrez les paramètres souhaités pour personnaliser votre PKI. 
</div> 
<p>La génération des clés de signature prend du temps, donc soyez patient :o)</p>
<div class="callout callout-danger">
  Le mot de passe de cette PKI doit être suffisement complexe et il conviendra de le sauvegarder en suivant les recommendations en vigueur.<br>
Toute perte de ce mot de passe rendra la PKI définitivement inutilisable. 
  </div>
  <div class="callout callout-info">
    Par défaut, les clés privées sont stockées au format <b>PKCS#8</b> et les clés publiques au format PEM. <br>
    Sur les stations blanches, l'ensemble des clés sont enregistrées dans /etc/keysas/.
    </div>
</section>

<section id="generation-des-cles-de-signature">
<h3>2 - Ajouter une station blanche</h3>
  <p>Ajouter ensuite votre nouvelle station <b>Keysas</b> dans <b>Keysas-admin</b> en cliquant sur <b>"Add a Keysas"</b>. Nommez votre station et renseignez son adresse IP.</p>
  <div class="callout callout-info">
  L'administration des différentes stations blanches à distance se fait par <b>SSH</b>. Il est donc nécessaire de créer une paire de clés <b>SSH</b> au format <b>Ed25519</b> sur la station d'administration pour que l'application puisse contrôler les stations à distance et de manière chiffrée.
  </div>
<p>Pour ce faire, ouvrez un terminal et entrez la ligne de commande suivante:<b></b></p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">ssh-keygen -m PEM -t ed25519 -f mykey</span>
</code></pre></div>
<p>Rendez-vous ensuite dans <b>Admin configuration/SSH configuration</b> pour renseigner le chemin vers vos clés fraichement générées. Allez ensuite dans <b>Manage your Keysas</b> puis cliquez sur <b>Export SSH pubkey</b>. Attendez que le status passe en vert à <b class="text-success">Online</b>. Appuyez ensuite sur <b>More...</b> puis <b>Enroll</b> pour générer les clés de signatures nécessaires sur la station distante..</p>


</section>
<section id="signature-d-un-peripherique-usb">
<h3>3 - Signature d’un périphérique USB</h3>
<p>Pour signer une nouvelle clé USB de sortie, allez dans le menu d'administration puis choisissez <b>"Sign a key"</b>. Renseignez le mot de passe de votre <b>IKPQPKI</b> et cliquez sur <b class="text-success">Sign</b>.<br>
Branchez simplement la nouvelle clé USB à signer sur la station d'administration et patientez jusqu'au message de confirmation vous indiquant quer le périphérique est correctement signé.</p>

<div class="callout callout-info">
  L'ensemble des périphériques signés seront valides pour toutes les stations <b>Keysas</b> enrollées avec votre <b>IKPQPKI</b>. 
</div>

<p>Vous pouvez maintenant formater le périphérique avec tout système de fichier supporté par la station blanche (ext2, ext3, ext4, fat32, exfat, ntfs)</p>

<p>Pour plus de documentation, rendez-vous sur <b>keysas.fr</b>.</p>
</section>
</section>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "AppWizard-fr",
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
