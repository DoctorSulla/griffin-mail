<script lang="ts">
	let { error = '', success = '' }: { error?: string; success?: string } = $props();
</script>

{#if error}
	<div
		class="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
		role="alert"
	>
		{error}
	</div>
{/if}

{#if success}
	<div
		class="rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700"
		role="status"
	>
		{success}
	</div>
{/if}
