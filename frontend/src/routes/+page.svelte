<script lang="ts">
	import { onMount } from 'svelte';
	import Users from '@lucide/svelte/icons/users';
	import List from '@lucide/svelte/icons/list';
	import Contact from '@lucide/svelte/icons/contact';
	import { api, type InstanceStats } from '$lib/api';

	let stats = $state<InstanceStats>();
	let error = $state('');

	onMount(async () => {
		const result = await api.getInstanceStats();
		if (result.ok && result.data) {
			stats = result.data;
		} else {
			error = result.message || 'Instance statistics could not be loaded';
		}
	});

	const cards = $derived([
		{ label: 'Recipients', value: stats?.recipients, icon: Contact },
		{ label: 'Mailing lists', value: stats?.lists, icon: List },
		{ label: 'Users', value: stats?.users, icon: Users }
	]);
</script>

<section class="py-8">
	<h1 class="text-3xl font-semibold text-blue-700">Griffin Mail</h1>
	<p class="mt-3 max-w-2xl text-lg text-gray-600">
		Welcome to Griffin Mail. Here is a summary of this running instance.
	</p>

	<h2 class="mt-10 text-xl font-semibold text-gray-900">Instance statistics</h2>
	{#if error}
		<p class="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-red-700" role="alert">
			{error}
		</p>
	{:else}
		<div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3" aria-busy={stats === undefined}>
			{#each cards as card}
				{@const Icon = card.icon}
				<div class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
					<div class="flex items-center justify-between">
						<p class="font-medium text-gray-600">{card.label}</p>
						<Icon size={24} class="text-blue-600" aria-hidden="true" />
					</div>
					{#if card.value === undefined}
						<div class="mt-4 h-10 w-20 animate-pulse rounded bg-gray-200"></div>
					{:else}
						<p class="mt-2 text-4xl font-semibold tracking-tight text-gray-900">
							{card.value.toLocaleString()}
						</p>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</section>
