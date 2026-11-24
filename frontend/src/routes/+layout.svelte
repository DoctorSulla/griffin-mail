<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';
	import { afterNavigate } from '$app/navigation';
	import { api } from '$lib/api';
	import { goto } from '$app/navigation';

	let { children } = $props();

	interface Route {
		text: string;
		href: string;
		allowed: 'always' | 'authenticated' | 'unauthenticated';
		navigation?: boolean;
	}

	let links: Route[] = $state([]);

	const routes: Route[] = [
		{ text: 'Home', href: '/', allowed: 'always' },
		{ text: 'Register', href: '/register', allowed: 'unauthenticated' },
		{ text: 'Login', href: '/login', allowed: 'unauthenticated' },
		{
			text: 'Reset password',
			href: '/resetPassword',
			allowed: 'unauthenticated',
			navigation: false
		},
		{ text: 'Unsubscribe', href: '/unsubscribe', allowed: 'always', navigation: false },
		{ text: 'Privacy Policy', href: '/privacy', allowed: 'always', navigation: false },
		{ text: 'Terms of Service', href: '/terms', allowed: 'always', navigation: false },
		{ text: 'Initial setup', href: '/setup', allowed: 'always', navigation: false },
		{ text: 'Lists', href: '/lists', allowed: 'authenticated' },
		{ text: 'List details', href: '/lists/detail', allowed: 'authenticated', navigation: false },
		{ text: 'Recipients', href: '/addRecipients', allowed: 'authenticated' },
		{ text: 'Create list', href: '/createList', allowed: 'authenticated', navigation: false },
		{ text: 'Permissions', href: '/permissions', allowed: 'authenticated' },
		{ text: 'Profile', href: '/profile', allowed: 'authenticated' },
		{ text: 'Media', href: '/media', allowed: 'authenticated' },
		{ text: 'Upload Media', href: '/uploadImage', allowed: 'authenticated' }
	];

	function currentRoute(): Route | null {
		return routes.find((route) => route.href === page.route.id) ?? null;
	}

	let title = $derived.by(() => {
		if (currentRoute()) {
			return currentRoute()?.text;
		}
		return 'Griffin Mail';
	});

	let loggedIn = $state(false);

	afterNavigate(async function () {
		let route = currentRoute();
		const setup = await api.getSetupStatus();
		if (setup.ok && setup.data?.needs_admin) {
			if (route?.href !== '/setup' && route?.href !== '/privacy' && route?.href !== '/terms') {
				goto('/setup');
			}
			return;
		}

		let response = await api.getProfile();
		if (response.response_type == 'Error') {
			loggedIn = false;
			links = routes.filter(
				(route) => route.navigation !== false && route.allowed !== 'authenticated'
			);
			if (route?.allowed == 'authenticated') {
				goto('/login');
			} else if (route?.href === '/setup') {
				goto('/');
			}
		} else {
			loggedIn = true;
			links = routes.filter(
				(route) => route.navigation !== false && route.allowed !== 'unauthenticated'
			);
			if (route?.allowed == 'unauthenticated') {
				goto('/profile');
			} else if (route?.href === '/setup') {
				goto('/profile');
			}
		}
	});

	async function logout() {
		await api.logout();
		goto('/login');
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{title}</title>
</svelte:head>

<div class="flex min-h-screen flex-col">
	<nav class="bg-blue-700 px-3 py-3">
		<div class="m-auto flex max-w-7xl flex-wrap items-center gap-x-5 gap-y-2">
			{#each links as link}
				<a class="font-medium text-white hover:text-blue-100" href={link.href}>{link.text}</a>
			{/each}
			{#if loggedIn}
				<button class="cursor-pointer font-medium text-white hover:text-blue-100" onclick={logout}>
					Logout
				</button>
			{/if}
		</div>
	</nav>
	<main class="m-auto w-full max-w-7xl flex-1 px-4">
		{@render children?.()}
	</main>
	<footer class="border-t border-gray-200 bg-white">
		<div
			class="m-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-4 text-sm text-gray-500"
		>
			<span>Griffin Mail</span>
			<div class="flex items-center gap-6">
				<a class="hover:text-gray-900" href="/privacy">Privacy Policy</a>
				<a class="hover:text-gray-900" href="/terms">Terms of Service</a>
			</div>
		</div>
	</footer>
</div>
