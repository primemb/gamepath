export const relayInvitePersian: Record<string, string> = {
  Share: 'اشتراک',
  More: 'بیشتر',
  'Relay options': 'گزینه‌های رله',
  'Manual configuration': 'تنظیم دستی',
  'Remove from app': 'حذف از برنامه',
  'Manage access': 'مدیریت دسترسی',
  'Manage relay access': 'مدیریت دسترسی رله',
  'VPS administration': 'مدیریت VPS',
  'Sign in with a VPS administrator account (root or sudo) to see and revoke enrolled clients. A relay invitation alone cannot manage access.':
    'برای دیدن و لغو دسترسی کاربران، با حساب مدیر VPS (root یا دارای sudo) وارد شوید. دعوت رله به‌تنهایی اجازه مدیریت دسترسی نمی‌دهد.',
  'The SSH connection stays open only for this dialog, for up to 15 minutes. Your password is never saved.':
    'اتصال SSH فقط برای این پنجره و حداکثر ۱۵ دقیقه باز می‌ماند. رمز شما هرگز ذخیره نمی‌شود.',
  'Signing in…': 'در حال ورود…',
  'View client access': 'نمایش دسترسی کاربران',
  'Enrolled clients': 'کاربران ثبت‌شده',
  'No enrolled clients.': 'هیچ کاربری ثبت نشده است.',
  'This PC': 'این رایانه',
  Revoke: 'لغو دسترسی',
  'Revoke access?': 'دسترسی لغو شود؟',
  'Confirm access revocation': 'تأیید لغو دسترسی',
  'This client will disconnect within a few seconds. Their invitation will stop working, and they will need a new one to reconnect. Other users stay connected.':
    'اتصال این کاربر ظرف چند ثانیه قطع می‌شود. دعوت او دیگر کار نمی‌کند و برای اتصال دوباره به دعوت جدید نیاز دارد. اتصال سایر کاربران برقرار می‌ماند.',
  'Keep access': 'نگه داشتن دسترسی',
  'Revoking…': 'در حال لغو…',
  'Revoke access': 'لغو دسترسی',
  'Access revoked. Other relay sessions keep running.': 'دسترسی لغو شد. اتصال سایر کاربران رله برقرار می‌ماند.',
  'Loading client access…': 'در حال بارگذاری دسترسی کاربران…',
  'Removing access affects this credential on every PC using it. Your current PC is protected here.':
    'لغو دسترسی بر همه رایانه‌های استفاده‌کننده از این اطلاعات دسترسی اثر می‌گذارد. دسترسی رایانه فعلی شما در این بخش محافظت می‌شود.',
  'Removing access affects this credential on every PC using it.':
    'لغو دسترسی بر همه رایانه‌های استفاده‌کننده از این اطلاعات دسترسی اثر می‌گذارد.',
  'Sign out': 'خروج از حساب',
  'Sign in to the VPS again to manage access': 'برای مدیریت دسترسی دوباره به VPS وارد شوید',
  'Use the configured relay address to manage access': 'برای مدیریت دسترسی از نشانی رله تنظیم‌شده استفاده کنید',
  'Another access request is still running': 'یک درخواست مدیریت دسترسی هنوز در حال اجراست',
  'You cannot revoke this PC from this dialog': 'در این پنجره نمی‌توانید دسترسی همین رایانه را لغو کنید',
  'The VPS returned an invalid client access list': 'فهرست دسترسی کاربران دریافتی از VPS معتبر نیست',
  'Update this VPS relay once to enable access management. Use Update VPS between games.':
    'برای فعال شدن مدیریت دسترسی، رله VPS را یک بار به‌روز کنید. گزینه به‌روزرسانی VPS را بین بازی‌ها اجرا کنید.',
  'Share with a friend': 'اشتراک با دوست',
  'Relay invitation': 'دعوت به رله',
  'Separate access': 'دسترسی مستقل',
  'Create a personal invitation so your friend can use this relay with their own VPN or proxy nodes.':
    'یک دعوت شخصی بسازید تا دوستتان بتواند با گره‌های VPN یا پراکسی خودش از این رله استفاده کند.',
  'Friend name': 'نام دوست',
  'e.g. Ali': 'مثلاً علی',
  'Your SSH password is used once and never included in the invitation.':
    'رمز SSH فقط برای همین کار استفاده می‌شود و در دعوت قرار نمی‌گیرد.',
  'Everyone stays connected': 'اتصال همه برقرار می‌ماند',
  'New access is picked up automatically within a few seconds. Existing relay sessions keep running.':
    'دسترسی جدید ظرف چند ثانیه به‌صورت خودکار فعال می‌شود. اتصال کاربران فعلی رله برقرار می‌ماند.',
  'GamePath signs in to your VPS and enrolls this PC while existing sessions keep running. Update older relays once to enable this.':
    'GamePath به VPS وارد می‌شود و این رایانه را بدون قطع اتصال کاربران فعلی ثبت می‌کند. برای فعال شدن این قابلیت، رله‌های قدیمی را یک بار به‌روز کنید.',
  'Update this VPS relay once to enable invitations without restarting. Use Update VPS between games; existing client credentials are preserved.':
    'برای دعوت بدون راه‌اندازی مجدد، رله VPS را یک بار به‌روز کنید. گزینه به‌روزرسانی VPS را بین بازی‌ها اجرا کنید؛ اطلاعات دسترسی کاربران فعلی حفظ می‌شود.',
  'Creating invitation…': 'در حال ساخت دعوت…',
  'Create invitation': 'ساخت دعوت',
  'Creating your friend’s relay access': 'در حال ساخت دسترسی رله برای دوست شما',
  'Invitation ready': 'دعوت آماده است',
  'Send the link or file privately to this friend. It includes the relay address, port, and their personal access credential.':
    'لینک یا فایل را خصوصی برای این دوست بفرستید. دعوت شامل نشانی و درگاه رله و اطلاعات دسترسی شخصی اوست.',
  'Copy invitation link': 'کپی لینک دعوت',
  'Save invitation file': 'ذخیره فایل دعوت',
  'Invitation link copied': 'لینک دعوت کپی شد',
  'Invitation file saved': 'فایل دعوت ذخیره شد',
  'On your friend’s PC': 'در رایانه دوست شما',
  'Open Game → Connection → Import shared relay.': 'بخش بازی ← اتصال ← وارد کردن رله اشتراکی را باز کنید.',
  'Import the copied link or invitation file.': 'لینک کپی‌شده یا فایل دعوت را وارد کنید.',
  'Choose the relay, add their nodes, and connect in Relay mode.':
    'رله را انتخاب کنید، گره‌های خودتان را اضافه کنید و در حالت رله متصل شوید.',
  'Anyone with this invitation can use its access. Create a separate invitation for each friend.':
    'هر کسی این دعوت را داشته باشد می‌تواند از دسترسی آن استفاده کند. برای هر دوست یک دعوت جداگانه بسازید.',
  'Import shared relay': 'وارد کردن رله اشتراکی',
  'Invited by a friend': 'دعوت از طرف دوست',
  'Your friend’s invitation adds the relay address and your personal access. You do not need their VPS login.':
    'دعوت دوست شما، نشانی رله و دسترسی شخصی شما را اضافه می‌کند. به اطلاعات ورود VPS او نیاز ندارید.',
  'Import from clipboard': 'وارد کردن از کلیپ‌بورد',
  'Copy your friend’s invitation link first.': 'ابتدا لینک دعوت دوستتان را کپی کنید.',
  'Choose invitation file': 'انتخاب فایل دعوت',
  'Open the .gprelay file they sent you.': 'فایل .gprelay دریافتی را باز کنید.',
  'Ready to add': 'آماده افزودن',
  'Relay address': 'نشانی رله',
  'Invited as': 'نام در دعوت',
  'You still need your own VPN or proxy nodes to reach this relay.':
    'برای دسترسی به این رله همچنان به گره‌های VPN یا پراکسی خودتان نیاز دارید.',
  'Reading invitation…': 'در حال خواندن دعوت…',
  'Adding relay…': 'در حال افزودن رله…',
  'Add relay': 'افزودن رله',
  'Shared relay added. Choose it and connect in Relay mode with your own nodes.':
    'رله اشتراکی اضافه شد. آن را انتخاب کنید و با گره‌های خودتان در حالت رله متصل شوید.',
  'This is not a valid GamePath relay invitation': 'این دعوت رله GamePath معتبر نیست',
  'Enter a friend name of up to 80 characters': 'نام دوست را با حداکثر ۸۰ نویسه وارد کنید',
  'Use the configured relay address to share this VPS': 'برای اشتراک این VPS از نشانی رله تنظیم‌شده استفاده کنید',
  'An invitation is already being created for this relay': 'یک دعوت برای این رله در حال ساخته شدن است',
  'This invitation has expired in the app. Import it or create it again.':
    'مهلت این دعوت در برنامه تمام شده است. دوباره آن را وارد کنید یا بسازید.',
  'Copying a real invitation is available in the Windows app.': 'کپی دعوت واقعی در برنامه ویندوز در دسترس است.',
  'Saving a real invitation is available in the Windows app.': 'ذخیره دعوت واقعی در برنامه ویندوز در دسترس است.',
}
