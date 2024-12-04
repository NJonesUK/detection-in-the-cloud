import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'Leonidas Documentation',
			social: {
				github: 'https://github.com/withsecurelabs/leonidas',
			},
			sidebar: [
				{
					label: 'TTPs',
					collapsed: true,
					items: [
						{
							label: 'Credential Access',
							collapsed: true,
							autogenerate: { directory: 'TTPs/credential_access' },
						},
						{
							label: 'Defense Evasion',
							collapsed: true,
							autogenerate: { directory: 'TTPs/defense_evasion' },
						},
						{
							label: 'Discovery',
							collapsed: true,
							autogenerate: { directory: 'TTPs/discovery'}
						},
						{
							label: 'Execution',
							collapsed: true,
							autogenerate: { directory: 'TTPs/execution'}
						},
						{
							label: 'Impact',
							collapsed: true,
							autogenerate: { directory: 'TTPs/impact'}
						},
						{
							label: 'Persistence',
							collapsed: true,
							autogenerate: { directory: 'TTPs/persistence'}
						},
						{
							label: 'Privilege Escalation',
							collapsed: true,
							autogenerate: { directory: 'TTPs/privilege_escalation'}
						}
					]
				},
				{
					label: "Leonidas Framework Documentation",
					collapsed: true,
					autogenerate: { directory: 'Leonidas Documentation'}
				}

			]
		}),
	],
});
