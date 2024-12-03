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
					label: 'Credential Access',
					collapsed: true,
					autogenerate: { directory: 'credential_access' },
				},
				{
					label: 'Defense Evasion',
					collapsed: true,
					autogenerate: { directory: 'defense_evasion' },
				},
				{
					label: 'Discovery',
					collapsed: true,
					autogenerate: { directory: 'discovery'}
				},
				{
					label: 'Execution',
					collapsed: true,
					autogenerate: { directory: 'execution'}
				},
				{
					label: 'Impact',
					collapsed: true,
					autogenerate: { directory: 'impact'}
				},
				{
					label: 'Persistence',
					collapsed: true,
					autogenerate: { directory: 'persistence'}
				},
				{
					label: 'Privilege Escalation',
					collapsed: true,
					autogenerate: { directory: 'privilege_escalation'}
				}
			]
		}),
	],
});
