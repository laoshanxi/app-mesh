const AppMeshClient = require('../src/appmesh_client');

async function userTest() {
    const appmesh = new AppMeshClient('https://localhost:6060');

    try {
        // Test login
        const token = await appmesh.login('admin', 'admin123');
        console.log('login response:', token);
        const auth = await appmesh.authentication(token)
        console.log('authentication response:', auth);
        // await appmesh.logout();


        // Test list applications
        const applications = await appmesh.app_view_all();
        console.log('app_view_all:', applications);

        const app_view = await appmesh.app_view('ping');
        console.log('app_view:', app_view);


        // Test logout
        await appmesh.logout();
        console.log('Logged out successfully');
    } catch (error) {
        console.error('Error:', error.message);
    }
}

userTest();