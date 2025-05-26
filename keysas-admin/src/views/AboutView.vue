

<script>
import NavBar from '../components/NavBar.vue'

export default {
  name: 'AboutView',
  components: {
    NavBar
  },

  data() {
    return {
    }
  },
}

</script>

<template>
  <div class="container">
    <NavBar />
    <div class="content">
      <h2>Keysas-admin. Version 2.6</h2>
      <h2>Please visit <a href="https://keysas.fr" class="website text-info">keysas.fr</a> to learn more </h2>
      <h3>&copy; Keysas 2022-2025.</h3>
    </div>
  </div>
</template>


<style lang="scss">
.container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
  min-height: 100vh;
}

.content {
  text-align: center;
  background: rgba(52, 58, 64, 0.9); // Semi-transparent background
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

h2 {
  color: #e9f1f3;
  margin-bottom: 10px;
}

h3 {
  font-weight: bold;
  color: #fff;
  font-size: 20px;
  margin-top: 20px;
}

.website {
  font-weight: normal;
  font-size: 1em;
  color: #17a2b8;
  text-decoration: none;
}

.website:hover {
  text-decoration: underline;
}
</style>