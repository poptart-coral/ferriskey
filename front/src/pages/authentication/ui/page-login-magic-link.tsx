import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Form, FormField } from '@/components/ui/form'
import { UseFormReturn } from 'react-hook-form'
import { MagicLinkSchema } from '@/pages/authentication/schemas/magic-link.schema'
import { MagicCard } from '@/components/magicui/magic-card'
import { InputText } from '@/components/ui/input-text'
import { Link } from 'react-router'
import { Schemas } from '@/api/api.client'

type RealmLoginSetting = Schemas.RealmLoginSetting

export interface PageLoginMagicLinkProps {
  form: UseFormReturn<MagicLinkSchema>
  onSubmit: (data: MagicLinkSchema) => void
  isLoading?: boolean
  isSuccess?: boolean
  error?: string | null
  loginSettings: RealmLoginSetting
}

export default function PageLoginMagicLink({
  form,
  onSubmit,
  isLoading,
  isSuccess,
  error,
}: PageLoginMagicLinkProps) {
  if (isSuccess) {
    return (
      <div className='flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10'>
        <div className='w-full max-w-sm md:max-w-3xl'>
          <Card className='overflow-hidden p-0'>
            <MagicCard className='p-0' gradientColor='#D9D9D955'>
              <CardContent className='p-6 md:p-8'>
                <div className='flex flex-col gap-4 text-center'>
                  <div className='rounded-lg bg-green-100 p-4'>
                    <h2 className='text-lg font-semibold text-green-900'>Check your email</h2>
                    <p className='text-sm text-green-700'>
                      We&apos;ve sent a magic link to your email address. Click the link to login to
                      your account.
                    </p>
                  </div>
                  <p className='text-sm text-muted-foreground'>
                    The link will expire in a few minutes.
                  </p>
                  <Link to='../' className='text-sm underline'>
                    Back to login
                  </Link>
                </div>
              </CardContent>
            </MagicCard>
          </Card>
        </div>
      </div>
    )
  }

  return (
    <div className='flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10'>
      <div className='w-full max-w-sm md:max-w-3xl'>
        <div className='flex flex-col gap-6'>
          <Card className='overflow-hidden p-0'>
            <MagicCard className='p-0' gradientColor='#D9D9D955'>
              <CardContent className='grid p-0 md:grid-cols-2'>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)}>
                    <div className='p-6 md:p-8'>
                      <div className='flex flex-col gap-6'>
                        <div className='flex flex-col items-center text-center'>
                          <h1 className='text-2xl font-bold'>Passwordless Login</h1>
                          <p className='text-balance text-muted-foreground'>
                            Enter your email and we&apos;ll send you a magic link
                          </p>
                        </div>

                        {error && (
                          <div className='rounded-lg border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive'>
                            {error}
                          </div>
                        )}

                        <div className='grid gap-2'>
                          <FormField
                            control={form.control}
                            name='email'
                            render={({ field }) => (
                              <InputText
                                {...field}
                                label='Email'
                                name='email'
                                type='email'
                                className='w-full'
                                error={form.formState.errors.email?.message}
                              />
                            )}
                          />
                        </div>

                        <Button type='submit' className='w-full' disabled={isLoading}>
                          {isLoading ? 'Sending...' : 'Send Magic Link'}
                        </Button>

                        <div className='text-center text-sm'>
                          <Link to='../' className='underline underline-offset-4'>
                            Back to standard login
                          </Link>
                        </div>
                      </div>
                    </div>
                  </form>
                </Form>
                <div className='relative hidden bg-muted md:block'>
                  <img
                    src='/logo_ferriskey.png'
                    alt='Image'
                    className='absolute inset-0 h-full w-full object-cover dark:brightness-[0.2] dark:grayscale'
                  />
                </div>
              </CardContent>
            </MagicCard>
          </Card>
        </div>
      </div>
    </div>
  )
}
