import React from 'react';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import Keycloak from 'keycloak-js';
import ReportPage from './components/ReportPage';

interface ExtendedKeycloakConfig extends Keycloak.KeycloakConfig {
  flow?: string;
  pkceMethod?: string;
  responseMode?: string;
  responseType?: string;
}

const keycloakConfig: ExtendedKeycloakConfig = {
  url: process.env.REACT_APP_KEYCLOAK_URL,
  realm: process.env.REACT_APP_KEYCLOAK_REALM || "",
  clientId: process.env.REACT_APP_KEYCLOAK_CLIENT_ID || "",
  flow: 'standard',
  pkceMethod: 'S256',
  responseMode: 'query',
  responseType: 'code'
};

const keycloak = new Keycloak(keycloakConfig);

const App: React.FC = () => {
  return (
    <ReactKeycloakProvider
      authClient={keycloak}
      initOptions={{
        pkceMethod: 'S256',
        flow: 'standard',
        checkLoginIframe: false
      }}
    >
      <div className="App">
        <ReportPage />
      </div>
    </ReactKeycloakProvider>
  );
};

export default App;
