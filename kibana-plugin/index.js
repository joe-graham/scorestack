import { resolve } from 'path';
import { existsSync } from 'fs';


import { i18n } from '@kbn/i18n';

import attributeRoute from './server/routes/attribute';

export default function (kibana) {
  return new kibana.Plugin({
    require: ['elasticsearch'],
    name: 'scorestack',
    uiExports: {
      app: {
        title: 'Scorestack',
        description: 'A Kibana plugin for viewing and modifying ScoreStack checks and attributes.',
        main: 'plugins/scorestack/app',
      },
      styleSheetPaths: [
        resolve(__dirname, 'public/app.scss'),
        resolve(__dirname, 'public/app.css'),
      ].find(p => existsSync(p)),
    },

    config(Joi) {
      return Joi.object({
        enabled: Joi.boolean().default(true),
      }).default();
    },

    // eslint-disable-next-line no-unused-vars
    init(server, options) {
      const xpackMainPlugin = server.plugins.xpack_main;
      if (xpackMainPlugin) {
        const featureId = 'scorestack';

        xpackMainPlugin.registerFeature({
          id: featureId,
          name: i18n.translate('scorestack.featureRegistry.featureName', {
            defaultMessage: 'scorestack',
          }),
          navLinkId: featureId,
          icon: 'questionInCircle',
          app: [featureId, 'kibana'],
          catalogue: [],
          privileges: {
            all: {
              api: [],
              savedObject: {
                all: [],
                read: [],
              },
              ui: ['show'],
            },
            read: {
              api: [],
              savedObject: {
                all: [],
                read: [],
              },
              ui: ['show'],
            },
          },
        });
      }

      // Add server routes and initialize the plugin here
      const dataCluster = server.plugins.elasticsearch.getCluster('data');

      attributeRoute(server, dataCluster);
    },
  });
}
